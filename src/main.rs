mod guard;
mod monitor;
mod state;
mod tui;

use anyhow::Result;
use state::AppState;
use std::sync::{Arc, Mutex};

fn main() -> Result<()> {
    let state = Arc::new(Mutex::new(AppState::new()));
    monitor::spawn(Arc::clone(&state));
    tui::run(state)
}
