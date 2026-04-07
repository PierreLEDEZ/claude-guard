use crate::guard;
use crate::state::{AppState, ClaudeInstance, LogLevel};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, RefreshKind, System};

const POLL_MS: u64 = 500;

#[derive(Clone)]
struct Known {
    cwd: PathBuf,
}

pub fn spawn(state: Arc<Mutex<AppState>>) {
    thread::spawn(move || run(state));
}

fn run(state: Arc<Mutex<AppState>>) {
    let mut sys = System::new_with_specifics(
        RefreshKind::nothing().with_processes(ProcessRefreshKind::everything()),
    );
    let mut known: HashMap<u32, Known> = HashMap::new();

    // Au démarrage : nettoyer les holders pointant vers des PIDs morts
    // (cas où claude_guard a crashé sans pouvoir restaurer)
    sys.refresh_processes(ProcessesToUpdate::All, true);
    let alive: HashSet<u32> = sys.processes().keys().map(|p| p.as_u32()).collect();
    guard::reap_dead_holders(&alive);
    if let Ok(mut s) = state.lock() {
        s.log(
            crate::state::LogLevel::Info,
            "Démarrage : holders morts nettoyés (récupération post-crash)",
        );
    }

    loop {
        let active = sync_processes(&mut sys, &mut known, &state);
        remove_stopped(&active, &mut known, &state);
        thread::sleep(Duration::from_millis(POLL_MS));
    }
}

fn is_claude(cmd: &[String]) -> bool {
    if cmd.is_empty() {
        return false;
    }
    let joined = cmd.join(" ").to_lowercase();
    if !joined.contains("claude") {
        return false;
    }
    let last = cmd.last().map(|s| s.to_lowercase()).unwrap_or_default();
    joined.contains("node") || last.ends_with("claude")
}

fn sync_processes(
    sys: &mut System,
    known: &mut HashMap<u32, Known>,
    state: &Arc<Mutex<AppState>>,
) -> HashSet<u32> {
    sys.refresh_processes(ProcessesToUpdate::All, true);
    let mut active = HashSet::new();

    for (pid, proc_) in sys.processes() {
        let cmd: Vec<String> = proc_
            .cmd()
            .iter()
            .map(|s| s.to_string_lossy().into_owned())
            .collect();
        if !is_claude(&cmd) {
            continue;
        }
        let pid_u32 = pid.as_u32();
        active.insert(pid_u32);

        let cpu = proc_.cpu_usage();
        let mem_mb = proc_.memory() / 1024 / 1024;

        if known.contains_key(&pid_u32) {
            if let Ok(mut s) = state.lock() {
                if let Some(inst) = s.instances.get_mut(&pid_u32) {
                    inst.cpu = cpu;
                    inst.mem_mb = mem_mb;
                }
            }
            continue;
        }

        let cwd = match proc_.cwd() {
            Some(c) => c.to_path_buf(),
            None => continue,
        };
        register_instance(pid_u32, cwd, cpu, mem_mb, known, state);
    }

    active
}

fn register_instance(
    pid: u32,
    cwd: PathBuf,
    cpu: f32,
    mem_mb: u64,
    known: &mut HashMap<u32, Known>,
    state: &Arc<Mutex<AppState>>,
) {
    let masked = guard::redact(&cwd, pid);
    let n = masked.len();
    let inst = ClaudeInstance {
        pid,
        cwd: cwd.clone(),
        masked_files: masked,
        cpu,
        mem_mb,
        started_at: chrono::Local::now().format("%H:%M:%S").to_string(),
    };
    known.insert(pid, Known { cwd });
    if let Ok(mut s) = state.lock() {
        s.add_instance(inst);
        s.log(
            LogLevel::Info,
            format!("Nouvelle instance PID={pid} → {n} fichier(s) masqué(s)"),
        );
    }
}

fn remove_stopped(
    current: &HashSet<u32>,
    known: &mut HashMap<u32, Known>,
    state: &Arc<Mutex<AppState>>,
) {
    let stopped: Vec<u32> = known
        .keys()
        .copied()
        .filter(|p| !current.contains(p))
        .collect();
    for pid in stopped {
        if let Some(k) = known.remove(&pid) {
            guard::restore(&k.cwd, pid);
            if let Ok(mut s) = state.lock() {
                s.remove_instance(pid);
                s.log(
                    LogLevel::Warn,
                    format!("Instance PID={pid} arrêtée → fichiers restaurés"),
                );
            }
        }
    }
}
