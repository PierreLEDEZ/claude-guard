use ignore::WalkBuilder;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

const SENSITIVE_NAMES: &[&str] = &[
    ".env",
    ".env.local",
    ".env.production",
    ".env.staging",
    ".env.development",
    ".envrc",
    ".netrc",
    ".pgpass",
    "secrets.json",
    "credentials.json",
    "serviceAccount.json",
];

const SENSITIVE_EXTS: &[&str] = &["pem", "key", "p12", "pfx", "tfvars"];

/// Répertoires qu'on ne traverse JAMAIS — code tiers, deps, build artifacts, vcs.
/// Voir certifi/grpc qui contiennent des dizaines de .pem légitimes.
const SKIP_DIRS: &[&str] = &[
    ".git",
    ".venv",
    "venv",
    "env",
    "node_modules",
    "target",
    "dist",
    "build",
    "__pycache__",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    ".next",
    ".nuxt",
    "vendor",
];

// ─────────────────────────── Manifest ───────────────────────────

#[derive(Serialize, Deserialize, Clone)]
struct ManifestEntry {
    original: PathBuf,
    backup: PathBuf,
    sha256: String,
    size: u64,
    created_at: String,
    /// PIDs des instances Claude qui « tiennent » ce fichier redacté.
    /// On ne restaure que quand cette liste devient vide.
    holders: Vec<u32>,
}

#[derive(Serialize, Deserialize, Default)]
struct Manifest {
    /// Clé : chemin absolu du fichier original (sous forme string).
    entries: HashMap<String, ManifestEntry>,
}

static MANIFEST_LOCK: Mutex<()> = Mutex::new(());

fn home_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    PathBuf::from(home).join(".claude_guard")
}

fn backup_root() -> PathBuf {
    home_dir().join("backups")
}

fn manifest_path() -> PathBuf {
    home_dir().join("manifest.json")
}

fn load_manifest() -> Manifest {
    fs::read_to_string(manifest_path())
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

/// Écriture atomique : tmp + rename. Évite la corruption sur crash en cours d'écriture.
fn save_manifest(m: &Manifest) {
    let path = manifest_path();
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let tmp = path.with_extension("json.tmp");
    if let Ok(json) = serde_json::to_string_pretty(m) {
        if fs::write(&tmp, json).is_ok() {
            let _ = fs::rename(&tmp, &path);
        }
    }
}

// ─────────────────────────── Helpers ───────────────────────────

fn is_sensitive(path: &Path) -> bool {
    let name = match path.file_name().and_then(|s| s.to_str()) {
        Some(n) => n,
        None => return false,
    };
    if SENSITIVE_NAMES.contains(&name) {
        return true;
    }
    if let Some(ext) = path.extension().and_then(|s| s.to_str()) {
        if SENSITIVE_EXTS.contains(&ext) {
            return true;
        }
    }
    false
}

fn backup_path(original: &Path) -> PathBuf {
    let abs = original
        .canonicalize()
        .unwrap_or_else(|_| original.to_path_buf());
    let stripped = abs.strip_prefix("/").unwrap_or(&abs);
    backup_root().join(stripped)
}

/// Walk avec deux couches de filtrage :
/// 1. **`.gitignore`-aware** via la crate `ignore` (la même que ripgrep) :
///    on respecte `.gitignore`, `.git/info/exclude`, le global gitignore et
///    les `.ignore`. Si le projet ignore `.venv/` dans son gitignore, on le
///    skippe automatiquement sans avoir à le coder en dur.
/// 2. **`SKIP_DIRS` en filet de sécurité** : si le projet n'a pas de gitignore
///    (ou s'il a oublié d'ignorer `.venv`), on skippe quand même les répertoires
///    notoirement dangereux. Defense in depth.
fn iter_files(dir: &Path) -> impl Iterator<Item = PathBuf> {
    WalkBuilder::new(dir)
        .follow_links(false)
        .hidden(false) // on veut toujours voir .env, .envrc, etc.
        .git_ignore(true)
        .git_exclude(true)
        .git_global(true)
        .ignore(true)
        .filter_entry(|e| {
            if e.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                let name = e.file_name().to_string_lossy();
                !SKIP_DIRS.contains(&name.as_ref())
            } else {
                true
            }
        })
        .build()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().map(|t| t.is_file()).unwrap_or(false))
        .map(|e| e.into_path())
}

fn is_binary_secret(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|s| s.to_str()),
        Some("pem" | "key" | "p12" | "pfx")
    )
}

fn sha256_file(path: &Path) -> Option<(String, u64)> {
    let bytes = fs::read(path).ok()?;
    let size = bytes.len() as u64;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    Some((format!("{:x}", hasher.finalize()), size))
}

// ─────────────────────────── Redaction par format ───────────────────────────

fn redact_env(content: &str) -> String {
    let mut out = String::new();
    for line in content.lines() {
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            out.push_str(line);
            out.push('\n');
            continue;
        }
        let work = trimmed.strip_prefix("export ").unwrap_or(trimmed);
        if let Some(eq) = work.find('=') {
            let prefix_len = line.len() - trimmed.len();
            let prefix = &line[..prefix_len];
            let key_end = (trimmed.len() - work.len()) + eq;
            out.push_str(prefix);
            out.push_str(&trimmed[..key_end + 1]);
            out.push('\n');
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

fn redact_json_value(v: &mut serde_json::Value) {
    use serde_json::Value;
    match v {
        Value::String(s) => *s = String::new(),
        Value::Number(_) => *v = Value::String(String::new()),
        Value::Array(a) => a.iter_mut().for_each(redact_json_value),
        Value::Object(o) => o.values_mut().for_each(redact_json_value),
        _ => {}
    }
}

fn redact_json(content: &str) -> String {
    match serde_json::from_str::<serde_json::Value>(content) {
        Ok(mut v) => {
            redact_json_value(&mut v);
            serde_json::to_string_pretty(&v).unwrap_or_default()
        }
        Err(_) => String::new(),
    }
}

fn redact_yaml_value(v: &mut serde_yml::Value) {
    use serde_yml::Value;
    match v {
        Value::String(s) => *s = String::new(),
        Value::Number(_) => *v = Value::String(String::new()),
        Value::Sequence(s) => s.iter_mut().for_each(redact_yaml_value),
        Value::Mapping(m) => m.iter_mut().for_each(|(_, val)| redact_yaml_value(val)),
        _ => {}
    }
}

fn redact_yaml(content: &str) -> String {
    match serde_yml::from_str::<serde_yml::Value>(content) {
        Ok(mut v) => {
            redact_yaml_value(&mut v);
            serde_yml::to_string(&v).unwrap_or_default()
        }
        Err(_) => String::new(),
    }
}

fn redact_toml_value(v: &mut toml::Value) {
    use toml::Value;
    match v {
        Value::String(s) => *s = String::new(),
        Value::Integer(_) | Value::Float(_) => *v = Value::String(String::new()),
        Value::Array(a) => a.iter_mut().for_each(redact_toml_value),
        Value::Table(t) => t.iter_mut().for_each(|(_, v)| redact_toml_value(v)),
        _ => {}
    }
}

fn redact_toml(content: &str) -> String {
    match content.parse::<toml::Value>() {
        Ok(mut v) => {
            redact_toml_value(&mut v);
            toml::to_string_pretty(&v).unwrap_or_default()
        }
        Err(_) => String::new(),
    }
}

fn detect_and_redact(path: &Path, content: &str) -> String {
    let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
    let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");

    if name.starts_with(".env") || name == ".envrc" || name == ".netrc" || name == ".pgpass" {
        return redact_env(content);
    }
    match ext {
        "json" => redact_json(content),
        "yml" | "yaml" => redact_yaml(content),
        "toml" | "tfvars" => redact_toml(content),
        _ => {
            if name.ends_with(".json") {
                redact_json(content)
            } else {
                String::new()
            }
        }
    }
}

// ─────────────────────────── API publique ───────────────────────────

/// Redacte les fichiers sensibles dans `dir`, en sauvegardant les originaux.
///
/// **Sécurités** :
/// 1. Skip des répertoires noise (`.venv`, `node_modules`, `.git`, `target`, …)
/// 2. **Si un backup existe déjà → on ne touche ni au backup ni au fichier.**
///    On ajoute simplement `pid` aux holders du manifest. Le fichier est
///    déjà redacté par une instance précédente, on devient juste un nouveau
///    « locataire ».
/// 3. Refcounting : chaque entrée garde la liste des PIDs qui la tiennent.
///    `restore()` ne restore réellement que quand la liste est vide.
/// 4. Manifest JSON `~/.claude_guard/manifest.json` avec sha256 + size pour audit.
pub fn redact(dir: &Path, pid: u32) -> Vec<PathBuf> {
    let _ = fs::create_dir_all(backup_root());

    let _guard = MANIFEST_LOCK.lock().unwrap();
    let mut manifest = load_manifest();
    let mut processed = Vec::new();

    for file in iter_files(dir) {
        if !is_sensitive(&file) {
            continue;
        }

        let bp = backup_path(&file);
        let key = file.to_string_lossy().into_owned();

        // ─── Cas A : un backup existe déjà (autre instance, ou run précédent)
        // On ne touche RIEN sur le filesystem. On ajoute juste pid aux holders.
        if bp.exists() {
            if let Some(entry) = manifest.entries.get_mut(&key) {
                if !entry.holders.contains(&pid) {
                    entry.holders.push(pid);
                }
            } else {
                // Backup orphelin (manifest perdu mais backup présent) :
                // on reconstruit une entrée pour pouvoir le restaurer plus tard.
                if let Some((sha, size)) = sha256_file(&bp) {
                    manifest.entries.insert(
                        key.clone(),
                        ManifestEntry {
                            original: file.clone(),
                            backup: bp.clone(),
                            sha256: sha,
                            size,
                            created_at: chrono::Local::now()
                                .format("%Y-%m-%d %H:%M:%S")
                                .to_string(),
                            holders: vec![pid],
                        },
                    );
                }
            }
            processed.push(file);
            continue;
        }

        // ─── Cas B : premier backup pour ce fichier
        if let Some(parent) = bp.parent() {
            let _ = fs::create_dir_all(parent);
        }

        let (sha, size) = match sha256_file(&file) {
            Some(s) => s,
            None => continue,
        };

        if fs::copy(&file, &bp).is_err() {
            continue;
        }

        // Vérif post-copy : sha du backup doit matcher l'original
        let backup_ok = sha256_file(&bp).map(|(h, _)| h == sha).unwrap_or(false);
        if !backup_ok {
            let _ = fs::remove_file(&bp);
            continue;
        }

        manifest.entries.insert(
            key,
            ManifestEntry {
                original: file.clone(),
                backup: bp.clone(),
                sha256: sha,
                size,
                created_at: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
                holders: vec![pid],
            },
        );
        save_manifest(&manifest);

        let redacted = if is_binary_secret(&file) {
            String::new()
        } else {
            match fs::read_to_string(&file) {
                Ok(content) => detect_and_redact(&file, &content),
                Err(_) => String::new(),
            }
        };

        if fs::write(&file, redacted).is_ok() {
            processed.push(file);
        }
    }

    save_manifest(&manifest);
    processed
}

/// Libère les fichiers tenus par `pid` dans `dir`. Ne restaure réellement que
/// les fichiers dont `pid` était le dernier holder.
///
/// Le `dir` est utilisé pour limiter le scope (on ne touche pas aux entrées
/// d'autres répertoires), mais le matching réel se fait sur les holders.
pub fn restore(dir: &Path, pid: u32) {
    let _guard = MANIFEST_LOCK.lock().unwrap();
    let mut manifest = load_manifest();
    let dir_str = dir.to_string_lossy().into_owned();

    let candidates: Vec<String> = manifest
        .entries
        .iter()
        .filter(|(k, e)| k.starts_with(&dir_str) && e.holders.contains(&pid))
        .map(|(k, _)| k.clone())
        .collect();

    for key in candidates {
        let entry = match manifest.entries.get_mut(&key) {
            Some(e) => e,
            None => continue,
        };

        // Retirer ce pid des holders
        entry.holders.retain(|p| *p != pid);

        // Encore d'autres holders ? On ne restaure pas, on garde le fichier
        // redacté pour les autres instances.
        if !entry.holders.is_empty() {
            continue;
        }

        // Dernier holder → restore réel
        let entry = entry.clone();

        if !entry.backup.exists() {
            manifest.entries.remove(&key);
            continue;
        }

        // Vérification d'intégrité avant écriture
        let backup_hash = sha256_file(&entry.backup).map(|(h, _)| h);
        if backup_hash.as_deref() != Some(entry.sha256.as_str()) {
            // Backup corrompu : on garde tout en l'état pour intervention
            // manuelle. On remet le pid dans holders pour rester cohérent.
            if let Some(e) = manifest.entries.get_mut(&key) {
                e.holders.push(pid);
            }
            continue;
        }

        if fs::copy(&entry.backup, &entry.original).is_ok() {
            let _ = fs::remove_file(&entry.backup);
            manifest.entries.remove(&key);
        }
    }

    save_manifest(&manifest);
}

/// Nettoie les holders pointant vers des PIDs qui n'existent plus. Utile au
/// démarrage de claude_guard pour récupérer après un crash où `restore` n'a
/// pas pu tourner. Si une entrée se retrouve sans holder, elle est restaurée.
pub fn reap_dead_holders(alive: &std::collections::HashSet<u32>) {
    let _guard = MANIFEST_LOCK.lock().unwrap();
    let mut manifest = load_manifest();

    let keys: Vec<String> = manifest.entries.keys().cloned().collect();
    for key in keys {
        let entry = match manifest.entries.get_mut(&key) {
            Some(e) => e,
            None => continue,
        };
        entry.holders.retain(|p| alive.contains(p));

        if !entry.holders.is_empty() {
            continue;
        }

        let entry = entry.clone();
        if entry.backup.exists() {
            let backup_hash = sha256_file(&entry.backup).map(|(h, _)| h);
            if backup_hash.as_deref() == Some(entry.sha256.as_str())
                && fs::copy(&entry.backup, &entry.original).is_ok()
            {
                let _ = fs::remove_file(&entry.backup);
            }
        }
        manifest.entries.remove(&key);
    }

    save_manifest(&manifest);
}
