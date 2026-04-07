use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;

const MAX_LOGS: usize = 200;

#[derive(Clone)]
pub struct ClaudeInstance {
    pub pid: u32,
    pub cwd: PathBuf,
    pub masked_files: Vec<PathBuf>,
    pub cpu: f32,
    pub mem_mb: u64,
    pub started_at: String,
}

#[derive(Clone, PartialEq)]
#[allow(dead_code)]
pub enum LogLevel {
    Info,
    Warn,
    Error,
}

#[derive(Clone)]
pub struct LogEntry {
    pub time: String,
    pub level: LogLevel,
    pub msg: String,
}

pub struct AppState {
    pub instances: HashMap<u32, ClaudeInstance>,
    pub instance_order: Vec<u32>,
    pub logs: VecDeque<LogEntry>,
    pub selected: Option<u32>,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            instances: HashMap::new(),
            instance_order: Vec::new(),
            logs: VecDeque::new(),
            selected: None,
        }
    }

    pub fn add_instance(&mut self, inst: ClaudeInstance) {
        let pid = inst.pid;
        if !self.instances.contains_key(&pid) {
            self.instance_order.push(pid);
        }
        self.instances.insert(pid, inst);
        if self.selected.is_none() {
            self.selected = Some(pid);
        }
    }

    pub fn remove_instance(&mut self, pid: u32) {
        self.instances.remove(&pid);
        if let Some(idx) = self.instance_order.iter().position(|p| *p == pid) {
            self.instance_order.remove(idx);
        }
        if self.selected == Some(pid) {
            self.selected = self.instance_order.first().copied();
        }
    }

    pub fn selected_instance(&self) -> Option<&ClaudeInstance> {
        self.selected.and_then(|p| self.instances.get(&p))
    }

    pub fn select_next(&mut self) {
        if self.instance_order.is_empty() {
            return;
        }
        let idx = self
            .selected
            .and_then(|p| self.instance_order.iter().position(|x| *x == p))
            .unwrap_or(0);
        let next = (idx + 1).min(self.instance_order.len() - 1);
        self.selected = Some(self.instance_order[next]);
    }

    pub fn select_prev(&mut self) {
        if self.instance_order.is_empty() {
            return;
        }
        let idx = self
            .selected
            .and_then(|p| self.instance_order.iter().position(|x| *x == p))
            .unwrap_or(0);
        let prev = idx.saturating_sub(1);
        self.selected = Some(self.instance_order[prev]);
    }

    pub fn log(&mut self, level: LogLevel, msg: impl Into<String>) {
        let time = chrono::Local::now().format("%H:%M:%S").to_string();
        self.logs.push_back(LogEntry {
            time,
            level,
            msg: msg.into(),
        });
        while self.logs.len() > MAX_LOGS {
            self.logs.pop_front();
        }
    }
}
