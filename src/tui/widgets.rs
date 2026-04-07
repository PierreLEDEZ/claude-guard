use crate::state::{AppState, LogLevel};
use ratatui::{
    Frame,
    layout::{Constraint, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, List, ListItem, Paragraph, Row, Table},
};

fn block(title: &str, color: Color) -> Block<'_> {
    Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(color))
        .title(Span::styled(
            format!(" {title} "),
            Style::default().fg(color).add_modifier(Modifier::BOLD),
        ))
}

fn truncate_left(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let start = s.len() - (max - 1);
    format!("…{}", &s[start..])
}

pub fn render_title(f: &mut Frame, area: Rect) {
    let line = Line::from(vec![
        Span::styled(
            "claude_guard",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("  "),
        Span::styled(
            "surveillance & redaction des instances Claude Code",
            Style::default().fg(Color::DarkGray),
        ),
    ]);
    let p = Paragraph::new(line).block(block("", Color::Cyan));
    f.render_widget(p, area);
}

pub fn render_table(f: &mut Frame, state: &AppState, area: Rect) {
    if state.instance_order.is_empty() {
        let p = Paragraph::new("Aucune instance Claude Code détectée…")
            .style(Style::default().fg(Color::DarkGray))
            .block(block("Instances", Color::Blue));
        f.render_widget(p, area);
        return;
    }

    let header = Row::new(vec!["PID", "Répertoire", "CPU%", "RAM MB", "Démarré"])
        .style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        );

    let inner_w = area.width.saturating_sub(2) as usize;
    let dir_w = inner_w.saturating_sub(7 + 6 + 7 + 9 + 4).max(20);

    let rows: Vec<Row> = state
        .instance_order
        .iter()
        .filter_map(|pid| state.instances.get(pid))
        .map(|inst| {
            let dir = truncate_left(&inst.cwd.display().to_string(), dir_w);
            let selected = state.selected == Some(inst.pid);
            let style = if selected {
                Style::default().fg(Color::Black).bg(Color::Cyan)
            } else {
                Style::default()
            };
            Row::new(vec![
                Cell::from(inst.pid.to_string()),
                Cell::from(dir),
                Cell::from(format!("{:.1}", inst.cpu)),
                Cell::from(inst.mem_mb.to_string()),
                Cell::from(inst.started_at.clone()),
            ])
            .style(style)
        })
        .collect();

    let widths = [
        Constraint::Length(7),
        Constraint::Min(20),
        Constraint::Length(6),
        Constraint::Length(7),
        Constraint::Length(9),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(block("Instances", Color::Blue));
    f.render_widget(table, area);
}

pub fn render_detail(f: &mut Frame, state: &AppState, area: Rect) {
    let inst = match state.selected_instance() {
        Some(i) => i,
        None => {
            let p = Paragraph::new("Sélectionnez une instance avec ↑↓")
                .style(Style::default().fg(Color::DarkGray))
                .block(block("Détail", Color::Magenta));
            f.render_widget(p, area);
            return;
        }
    };

    let mut items: Vec<ListItem> = vec![
        ListItem::new(Line::from(vec![
            Span::styled("PID         : ", Style::default().fg(Color::Yellow)),
            Span::raw(inst.pid.to_string()),
        ])),
        ListItem::new(Line::from(vec![
            Span::styled("Répertoire  : ", Style::default().fg(Color::Yellow)),
            Span::raw(inst.cwd.display().to_string()),
        ])),
        ListItem::new(Line::from(vec![
            Span::styled("CPU         : ", Style::default().fg(Color::Yellow)),
            Span::raw(format!("{:.1}%", inst.cpu)),
        ])),
        ListItem::new(Line::from(vec![
            Span::styled("RAM         : ", Style::default().fg(Color::Yellow)),
            Span::raw(format!("{} MB", inst.mem_mb)),
        ])),
        ListItem::new(Line::from(vec![
            Span::styled("Démarré     : ", Style::default().fg(Color::Yellow)),
            Span::raw(inst.started_at.clone()),
        ])),
        ListItem::new(Line::from(Span::styled(
            format!("Fichiers masqués ({}):", inst.masked_files.len()),
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ))),
    ];

    for f_path in &inst.masked_files {
        items.push(ListItem::new(Line::from(vec![
            Span::styled(" • ", Style::default().fg(Color::Red)),
            Span::raw(f_path.display().to_string()),
        ])));
    }

    let list = List::new(items).block(block("Détail", Color::Magenta));
    f.render_widget(list, area);
}

pub fn render_logs(f: &mut Frame, state: &AppState, area: Rect) {
    let items: Vec<ListItem> = state
        .logs
        .iter()
        .rev()
        .take(7)
        .map(|e| {
            let (label, color) = match e.level {
                LogLevel::Info => ("INFO ", Color::Green),
                LogLevel::Warn => ("WARN ", Color::Yellow),
                LogLevel::Error => ("ERROR", Color::Red),
            };
            ListItem::new(Line::from(vec![
                Span::styled(format!("[{}] ", e.time), Style::default().fg(Color::DarkGray)),
                Span::styled(label, Style::default().fg(color).add_modifier(Modifier::BOLD)),
                Span::raw(" "),
                Span::raw(e.msg.clone()),
            ]))
        })
        .collect();

    let list = List::new(items).block(block(
        "Logs   [q] quitter  [↑↓] naviguer",
        Color::DarkGray,
    ));
    f.render_widget(list, area);
}
