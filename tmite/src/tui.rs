//! Inline-viewport TUI for `tmite connect` (§7.4).
//!
//! Owns the `ConnectModel`, applies `UiEvent`s, and redraws an inline
//! ratatui viewport below the current prompt. Alt-screen is deliberately
//! not used: the pane content is fixed-size status, and scrollback above
//! stays visible.

use std::io::stdout;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use n0_future::StreamExt;
use ratatui::backend::CrosstermBackend;
use ratatui::crossterm::cursor::{Hide, MoveTo};
use ratatui::crossterm::event::{Event, EventStream, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use ratatui::layout::{Constraint, Layout};
use ratatui::style::{Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Row, Table};
use ratatui::{Frame, Terminal, TerminalOptions, Viewport};
use tokio::sync::Notify;
use tokio::sync::mpsc;

use tmite_core::client::model::{ConnectModel, SessionState};
const TICK: Duration = Duration::from_millis(500);
/// Status (Notice) messages disappear after this long.
const NOTICE_TTL: Duration = Duration::from_secs(5);

/// Restores the terminal on every exit path, including panics and `?`.
struct RawGuard;
impl Drop for RawGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = ratatui::crossterm::execute!(stdout(), ratatui::crossterm::cursor::Show);
    }
}

pub async fn run(
    mut rx: mpsc::UnboundedReceiver<tmite_core::client::model::UiEvent>,
    shutdown: Arc<Notify>,
    n_forwards: usize,
) -> Result<ConnectModel> {
    enable_raw_mode()?;
    let _guard = RawGuard;
    ratatui::crossterm::execute!(stdout(), Hide)?;

    let (_, term_rows) = ratatui::crossterm::terminal::size()?;
    let height = viewport_height(n_forwards, term_rows);
    let mut terminal = Terminal::with_options(
        CrosstermBackend::new(stdout()),
        TerminalOptions {
            viewport: Viewport::Inline(height),
        },
    )?;

    let mut model = ConnectModel::default();
    let mut events = EventStream::new();
    let mut tick = tokio::time::interval(TICK);
    let mut paused = false;
    // Viewport rect (terminal coords) from the last draw; needed to park
    // the cursor on exit. Must come from `Frame::area` (`CompletedFrame::area`
    // is the full terminal for inline viewports).
    let mut last_area = ratatui::layout::Rect::default();
    terminal.draw(|f| {
        last_area = f.area();
        render(&model, f);
    })?;

    loop {
        tokio::select! {
            maybe = rx.recv() => match maybe {
                Some(event) => model.apply(event),
                // All senders dropped: connect::run has finished.
                None => break,
            },
            _ = tick.tick() => {}
            event = events.next() => match event {
                Some(Ok(Event::Key(key))) if key.kind == KeyEventKind::Press => {
                    match key.code {
                        KeyCode::Char('q') => {
                            shutdown.notify_waiters();
                            break;
                        }
                        KeyCode::Char('c')
                            if key.modifiers.contains(KeyModifiers::CONTROL) =>
                        {
                            shutdown.notify_waiters();
                            break;
                        }
                        KeyCode::Char('p') => paused = !paused,
                        _ => {}
                    }
                }
                Some(Ok(_)) => {}
                // Stream errors are transient input glitches; keep going.
                _ => {}
            },
        }

        if let Some((at, _)) = &model.status
            && at.elapsed() > NOTICE_TTL
        {
            model.status = None;
        }
        if !paused {
            terminal.draw(|f| {
                last_area = f.area();
                render(&model, f);
            })?;
        }
    }
    // Clear the inline viewport before restoring the terminal. For inline
    // mode this clears from the viewport origin down, leaving scrollback
    // above untouched.
    terminal.clear()?;
    // `clear()` restores the cursor to its mid-viewport position; park it at
    // column 0 of the viewport's top row so the summary prints cleanly.
    ratatui::crossterm::execute!(stdout(), MoveTo(0, last_area.y))?;
    Ok(model)
}

/// Post-exit summary printed by `main` after the terminal is restored.
pub fn print_summary(model: &ConnectModel) {
    let up = model
        .started_at
        .map(|t| fmt_elapsed(t.elapsed()))
        .unwrap_or_else(|| "0s".into());
    println!(
        "tmite connect ended after {up} - {} ({})",
        model.server_name,
        short_node(&model.server_node),
    );
    // Closed connections' bytes live in the totals; active rows' last-ticked
    // bytes are still in `connections`.
    let tx = model.total_tx + model.connections.iter().map(|c| c.tx_bytes).sum::<u64>();
    let rx = model.total_rx + model.connections.iter().map(|c| c.rx_bytes).sum::<u64>();
    let served = model.closed_total + model.connections.len() as u64;
    println!(
        "served {served} connection(s) · {} ↑ · {} ↓",
        fmt_bytes(tx),
        fmt_bytes(rx)
    );
    for fwd in &model.forwards {
        println!("  {} → {}", fwd.local, fwd.target);
    }
}

/// Fixed viewport height: header + 3 path rows + forwards + 5 connection
/// rows + footer, clamped to the terminal.
fn viewport_height(n_forwards: usize, term_rows: u16) -> u16 {
    // header 1 + paths (3 data rows + header + borders) + forwards
    // (n data rows + header + borders) + connections (min 5 rows) + footer.
    let want = 19u16.saturating_add(n_forwards.min(10) as u16);
    want.min(term_rows.saturating_sub(2)).max(8)
}

/// Width cap for the dashboard: fits the widest pane content (paths with
/// long relay URLs, connection routes) without stretching on wide screens.
const MAX_WIDTH: u16 = 120;

fn render(model: &ConnectModel, f: &mut Frame) {
    let area = f.area();
    // Left-aligned so it lines up with the prompt above the viewport.
    let [area] = Layout::horizontal([Constraint::Length(area.width.min(MAX_WIDTH))]).areas(area);
    let forwards_h = model.forwards.len().min(10) as u16 + 3;
    let [header, paths, forwards, conns, footer] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(6),
        Constraint::Length(forwards_h),
        Constraint::Min(3),
        Constraint::Length(1),
    ])
    .areas(area);

    f.render_widget(header_line(model), header);
    render_paths(model, f, paths);
    render_forwards(model, f, forwards);
    render_connections(model, f, conns);
    f.render_widget(footer_line(model), footer);
}

fn header_line(model: &ConnectModel) -> Line<'static> {
    let mut spans = vec![
        "tmite connect ".bold(),
        Span::raw("→ "),
        model.server_name.clone().bold(),
        Span::raw(" "),
        Span::raw(format!("({}) ", short_node(&model.server_node))).dim(),
    ];
    match &model.session {
        Some(s) => {
            let (dot, label, green) = match s.state {
                SessionState::Established => ("●", "established", true),
                SessionState::Dialing => ("◐", "dialing…", false),
                SessionState::Reconnecting { .. } => ("◐", "reconnecting…", false),
            };
            let mut style = Style::new();
            if green {
                style = style.green();
            }
            spans.push(Span::styled(dot.to_string(), style));
            spans.push(Span::raw(" "));
            spans.push(Span::styled(label.to_string(), style));
            if s.redials > 0 {
                spans.push(Span::raw(format!(" · {} re-dial(s)", s.redials)));
            }
        }
        None => spans.push(Span::raw("starting…").dim()),
    }
    if let Some(started) = model.started_at {
        spans.push(Span::raw(format!(
            " · up {}",
            fmt_elapsed(started.elapsed())
        )));
    }
    Line::from(spans)
}

fn render_paths(model: &ConnectModel, f: &mut Frame, area: ratatui::layout::Rect) {
    let block = Block::bordered().title(" paths ".bold());
    let inner = block.inner(area);
    f.render_widget(block, area);

    let rows = model.paths.iter().take(inner.height as usize).map(|p| {
        let marker = if p.selected { "●" } else { "○" };
        let marker_style = if p.selected {
            Style::new().green().bold()
        } else {
            Style::new().dim()
        };
        Row::new([
            Span::styled(marker.to_string(), marker_style),
            Span::raw(if p.relay { "relay" } else { "direct" }),
            Span::raw(p.remote_addr.clone()),
            Span::raw(match p.rtt {
                Some(rtt) => format!("{} ms", rtt.as_millis()),
                None => "–".to_string(),
            })
            .dim(),
            Span::raw(fmt_bytes(p.tx_bytes)),
            Span::raw(fmt_bytes(p.rx_bytes)),
        ])
    });
    let table = Table::new(
        rows,
        [
            Constraint::Length(2),
            Constraint::Length(7),
            Constraint::Min(10),
            Constraint::Length(9),
            Constraint::Length(9),
            Constraint::Length(9),
        ],
    )
    .header(Row::new(["", "kind", "remote", "rtt", "tx", "rx"]).style(Style::new().dim()));
    f.render_widget(table, inner);
}

fn render_forwards(model: &ConnectModel, f: &mut Frame, area: ratatui::layout::Rect) {
    let block = Block::bordered().title(" forwards ".bold());
    let inner = block.inner(area);
    f.render_widget(block, area);

    let active = model.active_per_forward();
    let rows = model
        .forwards
        .iter()
        .take(inner.height as usize)
        .enumerate()
        .map(|(idx, fwd)| {
            Row::new([
                Span::raw(fwd.local.clone()),
                Span::raw("→ ".to_string()),
                Span::raw(fwd.target.clone()),
                Span::raw(active.get(idx).map(|n| n.to_string()).unwrap_or_default()),
            ])
        });
    let table = Table::new(
        rows,
        [
            Constraint::Min(12),
            Constraint::Length(2),
            Constraint::Min(12),
            Constraint::Length(6),
        ],
    )
    .header(Row::new(["local", "", "target", "active"]).style(Style::new().dim()));
    f.render_widget(table, inner);
}

fn render_connections(model: &ConnectModel, f: &mut Frame, area: ratatui::layout::Rect) {
    let title = format!(" connections ({}) ", model.connections.len());
    let block = Block::bordered().title(title.bold());
    let inner = block.inner(area);
    f.render_widget(block, area);

    let rows = model
        .connections
        .iter()
        .take(inner.height as usize)
        .map(|c| {
            let local_port = model
                .forwards
                .get(c.spec)
                .and_then(|f| f.local.rsplit(':').next())
                .unwrap_or("?");
            let route = model
                .forwards
                .get(c.spec)
                .map(|f| format!(":{local_port} → {}", f.target))
                .unwrap_or_else(|| "? → ?".to_string());
            Row::new([
                Span::raw(c.peer.clone()),
                Span::raw(route),
                Span::raw(fmt_elapsed(c.opened_at.elapsed())).dim(),
                Span::raw(fmt_bytes(c.tx_bytes)),
                Span::raw(fmt_bytes(c.rx_bytes)),
            ])
        });
    let table = Table::new(
        rows,
        [
            Constraint::Min(16),
            Constraint::Min(14),
            Constraint::Length(7),
            Constraint::Length(9),
            Constraint::Length(9),
        ],
    )
    .header(Row::new(["client", "route", "age", "tx", "rx"]).style(Style::new().dim()));
    f.render_widget(table, inner);
}

fn footer_line(model: &ConnectModel) -> Line<'static> {
    if let Some((_, msg)) = &model.status {
        return Line::from(Span::styled(msg.clone(), Style::new().yellow()));
    }
    let mut line = Line::from(Span::raw("q quit · p pause").dim());
    if model.closed_total > 0 {
        line.push_span(Span::raw(format!(" · {} closed", model.closed_total)).dim());
    }
    line
}

fn short_node(node: &str) -> &str {
    // iroh NodeIds are long; the first segment is enough to identify.
    match node.char_indices().nth(12) {
        Some((idx, _)) => &node[..idx],
        None => node,
    }
}

fn fmt_elapsed(d: Duration) -> String {
    let secs = d.as_secs();
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m{}s", secs / 60, secs % 60)
    } else {
        format!("{}h{:02}m", secs / 3600, (secs % 3600) / 60)
    }
}

fn fmt_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1000.0 && unit < UNITS.len() - 1 {
        value /= 1000.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tmite_core::client::model::{ForwardRow, PathRow, SessionState, SessionStatus, UiEvent};

    fn sample_model() -> ConnectModel {
        let mut m = ConnectModel::default();
        for ev in [
            UiEvent::Server {
                name: "homelab".into(),
                node: "z6h7abc123def456".into(),
            },
            UiEvent::Forwards(vec![ForwardRow {
                local: "0.0.0.0:2222".into(),
                target: "localhost:22".into(),
            }]),
            UiEvent::SessionState(SessionStatus {
                state: SessionState::Established,
                redials: 1,
            }),
            UiEvent::Started,
            UiEvent::ConnectionOpened {
                id: 1,
                peer: "127.0.0.1:55123".into(),
                spec: 0,
            },
            UiEvent::ConnectionBytes {
                id: 1,
                tx: 3_200_000,
                rx: 1_100_000,
            },
            UiEvent::Paths(vec![
                PathRow {
                    remote_addr: "192.168.1.20:54321".into(),
                    relay: false,
                    selected: true,
                    rtt: Some(Duration::from_millis(11)),
                    tx_bytes: 1_200_000,
                    rx_bytes: 8_400_000,
                },
                PathRow {
                    remote_addr: "use1-1.relay.iroh.link".into(),
                    relay: true,
                    selected: false,
                    rtt: Some(Duration::from_millis(44)),
                    tx_bytes: 512,
                    rx_bytes: 1_024,
                },
            ]),
        ] {
            m.apply(ev);
        }
        m
    }

    #[test]
    fn render_shows_panes() {
        let model = sample_model();
        let backend = ratatui::backend::TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| render(&model, f)).unwrap();
        let buf = terminal.backend().buffer();
        let text: String = buf.content.iter().map(|c| c.symbol()).collect();
        assert!(text.contains("tmite connect"), "header: {text}");
        assert!(text.contains("homelab"), "header: {text}");
        assert!(text.contains("established"), "header: {text}");
        assert!(text.contains("1.2 MB"), "path bytes: {text}");
        assert!(text.contains("11 ms"), "path rtt: {text}");
        assert!(text.contains("0.0.0.0:2222"), "forwards: {text}");
        assert!(text.contains("localhost:22"), "forwards: {text}");
        assert!(text.contains("connections (1)"), "conns: {text}");
        assert!(text.contains("127.0.0.1:55123"), "conn peer: {text}");
        assert!(text.contains(":2222 → localhost:22"), "conn route: {text}");
        assert!(text.contains("3.2 MB"), "conn bytes: {text}");
    }

    #[test]
    fn fmt_helpers() {
        assert_eq!(fmt_bytes(0), "0 B");
        assert_eq!(fmt_bytes(999), "999 B");
        assert_eq!(fmt_bytes(1500), "1.5 KB");
        assert_eq!(fmt_elapsed(Duration::from_secs(59)), "59s");
        assert_eq!(fmt_elapsed(Duration::from_secs(252)), "4m12s");
        assert_eq!(fmt_elapsed(Duration::from_secs(3720)), "1h02m");
        assert_eq!(short_node("z6h7abc123def456"), "z6h7abc123de");
        assert_eq!(short_node("short"), "short");
    }
}
