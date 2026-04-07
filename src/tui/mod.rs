pub mod layout;
pub mod widgets;

use crate::state::AppState;
use anyhow::Result;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{Terminal, backend::CrosstermBackend};
use std::io::{Stdout, stdout};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const TICK_MS: u64 = 250;

struct TermGuard;

impl Drop for TermGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(stdout(), LeaveAlternateScreen, DisableMouseCapture);
    }
}

fn setup_terminal() -> Result<(Terminal<CrosstermBackend<Stdout>>, TermGuard)> {
    enable_raw_mode()?;
    let mut out = stdout();
    execute!(out, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(out);
    let terminal = Terminal::new(backend)?;
    Ok((terminal, TermGuard))
}

pub fn run(state: Arc<Mutex<AppState>>) -> Result<()> {
    let (mut terminal, _guard) = setup_terminal()?;
    event_loop(&mut terminal, state)?;
    Ok(())
}

fn event_loop(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    state: Arc<Mutex<AppState>>,
) -> Result<()> {
    let tick = Duration::from_millis(TICK_MS);
    loop {
        {
            let s = state.lock().unwrap();
            terminal.draw(|f| {
                let areas = layout::build(f.area());
                widgets::render_title(f, areas.title);
                widgets::render_table(f, &s, areas.table);
                widgets::render_detail(f, &s, areas.detail);
                widgets::render_logs(f, &s, areas.logs);
            })?;
        }

        if event::poll(tick)? {
            if let Event::Key(k) = event::read()? {
                match k.code {
                    KeyCode::Char('q') | KeyCode::Esc => break,
                    KeyCode::Down => state.lock().unwrap().select_next(),
                    KeyCode::Up => state.lock().unwrap().select_prev(),
                    _ => {}
                }
            }
        }
    }
    Ok(())
}
