use ratatui::layout::{Constraint, Direction, Layout, Rect};

pub struct Areas {
    pub title: Rect,
    pub table: Rect,
    pub detail: Rect,
    pub logs: Rect,
}

pub fn build(area: Rect) -> Areas {
    let vert = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(10),
            Constraint::Length(10),
        ])
        .split(area);

    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
        .split(vert[1]);

    Areas {
        title: vert[0],
        table: body[0],
        detail: body[1],
        logs: vert[2],
    }
}
