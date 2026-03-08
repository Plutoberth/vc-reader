//! Interactive terminal file browser for a mounted volume.
//!
//! Built on `ratatui` + `crossterm`. The volume's flat entry list (from
//! [`Filesystem::list`]) is turned into an in-memory tree that the user can
//! navigate. From any node they can:
//!
//!   * descend into / out of directories,
//!   * view info about a file or directory,
//!   * extract a single file, or
//!   * extract a whole directory recursively.
//!
//! Extraction temporarily drops out of the alternate screen so the regular
//! [`indicatif`] progress bar (rate + ETA) is visible, then resumes the UI.

use std::fs;
use std::io::{self, Stdout, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::{Block, Borders, Clear, Gauge, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::{Frame, Terminal};

use vc_reader::fs::{Entry, Filesystem};

type Tui = Terminal<CrosstermBackend<Stdout>>;

/// Minimum gap between progress redraws, so streaming a file doesn't repaint
/// the screen thousands of times per second.
const REDRAW_INTERVAL: Duration = Duration::from_millis(60);

/// One node in the browsable tree. Children are stored as arena indices so the
/// tree needs no lifetimes or reference-counting.
struct Node {
    name: String,
    path: String,
    is_dir: bool,
    size: u64,
    children: Vec<usize>,
}

/// Launch the browser against a mounted filesystem. Sets up and tears down the
/// terminal, returning once the user quits.
pub fn run(filesystem: &mut dyn Filesystem) -> io::Result<()> {
    let entries = filesystem
        .list()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("listing failed: {e}")))?;
    let nodes = build_tree(entries);

    let mut browser = Browser {
        filesystem,
        nodes,
        stack: vec![0],
        state: ListState::default().with_selected(Some(0)),
        popup: None,
    };

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let mut terminal = Terminal::new(CrosstermBackend::new(stdout))?;

    let result = browser.event_loop(&mut terminal);

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    result
}

struct Browser<'a> {
    filesystem: &'a mut dyn Filesystem,
    nodes: Vec<Node>,
    /// Directory node indices from the root down to the current directory.
    stack: Vec<usize>,
    /// Cursor within the current directory's children.
    state: ListState,
    /// Modal info text; when set, the next key press dismisses it.
    popup: Option<String>,
}

impl Browser<'_> {
    fn event_loop(&mut self, terminal: &mut Tui) -> io::Result<()> {
        loop {
            terminal.draw(|frame| self.draw(frame))?;

            let Event::Key(key) = event::read()? else { continue };
            if key.kind != KeyEventKind::Press {
                continue;
            }
            // Any key closes an open popup.
            if self.popup.is_some() {
                self.popup = None;
                continue;
            }

            match key.code {
                KeyCode::Char('q') | KeyCode::Esc => break,
                KeyCode::Down | KeyCode::Char('j') => self.move_cursor(1),
                KeyCode::Up | KeyCode::Char('k') => self.move_cursor(-1),
                KeyCode::Enter | KeyCode::Right | KeyCode::Char('l') => self.enter(),
                KeyCode::Left | KeyCode::Char('h') | KeyCode::Backspace => self.go_up(),
                KeyCode::Char('i') => self.show_info(),
                KeyCode::Char('e') => self.extract_selected(terminal)?,
                _ => {}
            }
        }
        Ok(())
    }

    // --- navigation ----------------------------------------------------------

    fn current_dir(&self) -> usize {
        *self.stack.last().expect("stack is never empty")
    }

    fn children(&self) -> &[usize] {
        &self.nodes[self.current_dir()].children
    }

    fn selected_node(&self) -> Option<usize> {
        let sel = self.state.selected()?;
        self.children().get(sel).copied()
    }

    fn move_cursor(&mut self, delta: isize) {
        let len = self.children().len();
        if len == 0 {
            return;
        }
        let cur = self.state.selected().unwrap_or(0) as isize;
        let next = (cur + delta).rem_euclid(len as isize) as usize;
        self.state.select(Some(next));
    }

    fn enter(&mut self) {
        let Some(idx) = self.selected_node() else { return };
        if self.nodes[idx].is_dir {
            self.stack.push(idx);
            self.state
                .select(if self.children().is_empty() { None } else { Some(0) });
        } else {
            self.show_info();
        }
    }

    fn go_up(&mut self) {
        if self.stack.len() > 1 {
            let left = self.stack.pop().unwrap();
            // Restore the cursor onto the directory we came out of.
            let pos = self.children().iter().position(|&c| c == left).unwrap_or(0);
            self.state.select(Some(pos));
        }
    }

    fn current_path_display(&self) -> String {
        let path = &self.nodes[self.current_dir()].path;
        format!("/{path}")
    }

    // --- info ----------------------------------------------------------------

    fn show_info(&mut self) {
        let Some(idx) = self.selected_node() else { return };
        let node = &self.nodes[idx];
        self.popup = Some(if node.is_dir {
            let (files, dirs, total) = subtree_stats(&self.nodes, idx);
            format!(
                "Directory  /{}\n\n\
                 Contains : {files} file(s), {dirs} subdir(s)\n\
                 Total    : {}\n\n\
                 e = extract recursively   any key = close",
                node.path,
                human_size(total),
            )
        } else {
            format!(
                "File  /{}\n\n\
                 Size : {} ({} bytes)\n\n\
                 e = extract   any key = close",
                node.path,
                human_size(node.size),
                node.size,
            )
        });
    }

    // --- extraction ----------------------------------------------------------

    /// Extract the current selection, rendering a progress screen inside the
    /// TUI, then wait for a key press to return to the browser.
    fn extract_selected(&mut self, terminal: &mut Tui) -> io::Result<()> {
        let Some(idx) = self.selected_node() else { return Ok(()) };

        let (title, base, jobs) = self.plan_extraction(idx);
        let bytes_total = jobs.iter().map(|(_, size, _)| *size).sum();
        let mut state = ExtractState::new(title, jobs.len(), bytes_total);

        let result = self.run_jobs(terminal, &mut state, &base, &jobs);
        state.finished = Some(result.map(|()| jobs.len()).map_err(|e| e.to_string()));

        // Hold the completion screen until the user acknowledges it.
        loop {
            terminal.draw(|frame| draw_extract(frame, &state))?;
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    break;
                }
            }
        }
        Ok(())
    }

    /// Work out what to extract: a display title, the base output directory to
    /// create, and the list of (source path, size, output path) jobs.
    fn plan_extraction(&self, idx: usize) -> (String, PathBuf, Vec<(String, u64, PathBuf)>) {
        let node = &self.nodes[idx];
        if !node.is_dir {
            let out = PathBuf::from(&node.name);
            let title = format!("Extracting file  {}", node.name);
            return (title, PathBuf::new(), vec![(node.path.clone(), node.size, out)]);
        }

        let base = PathBuf::from(&node.name);
        let strip = node.path.len() + 1; // drop "<dir>/" from descendant paths
        let mut jobs = Vec::new();
        collect_files(&self.nodes, idx, &base, strip, &mut jobs);
        let title = format!("Extracting directory  {}/", node.name);
        (title, base, jobs)
    }

    /// Run every extraction job, repainting the progress screen as bytes stream.
    fn run_jobs(
        &mut self,
        terminal: &mut Tui,
        state: &mut ExtractState,
        base: &Path,
        jobs: &[(String, u64, PathBuf)],
    ) -> io::Result<()> {
        if !base.as_os_str().is_empty() {
            fs::create_dir_all(base)?;
        }

        for (index, (path, size, out)) in jobs.iter().enumerate() {
            if let Some(parent) = out.parent() {
                fs::create_dir_all(parent)?;
            }
            state.start_file(index, file_name(out), *size);
            terminal.draw(|frame| draw_extract(frame, state))?;

            let file = fs::File::create(out)?;
            let mut writer = ProgressWriter {
                inner: file,
                terminal: &mut *terminal,
                state: &mut *state,
                last_draw: Instant::now(),
            };
            self.filesystem.extract(path, &mut writer)?;
            drop(writer);
            state.finish_file();
        }
        Ok(())
    }

    // --- rendering -----------------------------------------------------------

    fn draw(&mut self, frame: &mut Frame) {
        let area = frame.area();
        let rows = Layout::vertical([
            Constraint::Length(3),
            Constraint::Min(1),
            Constraint::Length(3),
        ])
        .split(area);

        let header = Paragraph::new(self.current_path_display()).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" VeraCrypt Browser "),
        );
        frame.render_widget(header, rows[0]);

        let items: Vec<ListItem> = self
            .children()
            .iter()
            .map(|&c| {
                let n = &self.nodes[c];
                let label = if n.is_dir {
                    format!("[DIR]  {}/", n.name)
                } else {
                    format!("       {:<28} {:>10}", n.name, human_size(n.size))
                };
                ListItem::new(label)
            })
            .collect();

        let list = List::new(items)
            .block(Block::default().borders(Borders::ALL).title(" Files "))
            .highlight_style(Style::default().add_modifier(Modifier::REVERSED))
            .highlight_symbol(">> ");
        frame.render_stateful_widget(list, rows[1], &mut self.state);

        let hints = "up/down move    enter/right open    left/bksp up    e extract    i info    q quit";
        let footer = Paragraph::new(hints).block(Block::default().borders(Borders::ALL));
        frame.render_widget(footer, rows[2]);

        if let Some(text) = &self.popup {
            let popup = centered_rect(60, 40, area);
            frame.render_widget(Clear, popup);
            frame.render_widget(
                Paragraph::new(text.clone())
                    .block(Block::default().borders(Borders::ALL).title(" Info "))
                    .wrap(Wrap { trim: true }),
                popup,
            );
        }
    }
}

// --- free helpers ------------------------------------------------------------

/// Build the arena tree from a flat list of entries. Node 0 is the synthetic
/// root (empty path).
fn build_tree(mut entries: Vec<Entry>) -> Vec<Node> {
    use std::collections::HashMap;

    let mut nodes = vec![Node {
        name: "/".into(),
        path: String::new(),
        is_dir: true,
        size: 0,
        children: Vec::new(),
    }];
    let mut index: HashMap<String, usize> = HashMap::new();
    index.insert(String::new(), 0);

    // Parents sort before their children, so ancestors always exist first.
    entries.sort_by(|a, b| a.path.cmp(&b.path));
    for entry in entries {
        let parent_path = match entry.path.rfind('/') {
            Some(slash) => entry.path[..slash].to_string(),
            None => String::new(),
        };
        let parent = *index.get(&parent_path).unwrap_or(&0);
        let name = entry.path.rsplit('/').next().unwrap_or(&entry.path).to_string();

        let idx = nodes.len();
        nodes.push(Node {
            name,
            path: entry.path.clone(),
            is_dir: entry.is_dir,
            size: entry.size,
            children: Vec::new(),
        });
        nodes[parent].children.push(idx);
        index.insert(entry.path, idx);
    }

    // Sort each directory's children: directories first, then by name.
    for i in 0..nodes.len() {
        let mut children = std::mem::take(&mut nodes[i].children);
        children.sort_by(|&a, &b| {
            let (na, nb) = (&nodes[a], &nodes[b]);
            nb.is_dir
                .cmp(&na.is_dir)
                .then_with(|| na.name.to_lowercase().cmp(&nb.name.to_lowercase()))
        });
        nodes[i].children = children;
    }
    nodes
}

/// Collect every file under `idx`, paired with its size and the output path it
/// should be written to (relative to the extraction base directory).
fn collect_files(
    nodes: &[Node],
    idx: usize,
    base: &Path,
    strip: usize,
    out: &mut Vec<(String, u64, PathBuf)>,
) {
    for &child in &nodes[idx].children {
        let node = &nodes[child];
        if node.is_dir {
            collect_files(nodes, child, base, strip, out);
        } else {
            let relative = &node.path[strip..];
            out.push((node.path.clone(), node.size, base.join(relative)));
        }
    }
}

/// Count files, subdirectories, and total byte size under `idx`.
fn subtree_stats(nodes: &[Node], idx: usize) -> (usize, usize, u64) {
    let (mut files, mut dirs, mut total) = (0, 0, 0);
    for &child in &nodes[idx].children {
        let node = &nodes[child];
        if node.is_dir {
            dirs += 1;
            let (f, d, t) = subtree_stats(nodes, child);
            files += f;
            dirs += d;
            total += t;
        } else {
            files += 1;
            total += node.size;
        }
    }
    (files, dirs, total)
}

/// Last path component of `out` as a display string.
fn file_name(out: &Path) -> String {
    out.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| out.to_string_lossy().into_owned())
}

/// Progress of an in-flight extraction, shared between the writer (which updates
/// it) and [`draw_extract`] (which renders it).
struct ExtractState {
    title: String,
    files_total: usize,
    /// 1-based index of the file currently being written.
    file_index: usize,
    current_name: String,
    current_size: u64,
    current_written: u64,
    /// Bytes from files already fully written.
    bytes_done: u64,
    bytes_total: u64,
    started: Instant,
    /// `Some` once finished: `Ok(files)` or `Err(message)`.
    finished: Option<Result<usize, String>>,
}

impl ExtractState {
    fn new(title: String, files_total: usize, bytes_total: u64) -> Self {
        Self {
            title,
            files_total,
            file_index: 0,
            current_name: String::new(),
            current_size: 0,
            current_written: 0,
            bytes_done: 0,
            bytes_total,
            started: Instant::now(),
            finished: None,
        }
    }

    fn start_file(&mut self, index0: usize, name: String, size: u64) {
        self.file_index = index0 + 1;
        self.current_name = name;
        self.current_size = size;
        self.current_written = 0;
    }

    fn finish_file(&mut self) {
        self.bytes_done += self.current_written;
        self.current_written = 0;
    }

    fn bytes_written(&self) -> u64 {
        self.bytes_done + self.current_written
    }
}

/// A `Write` adapter that writes to a file while updating and repainting the
/// in-TUI progress screen.
struct ProgressWriter<'a> {
    inner: fs::File,
    terminal: &'a mut Tui,
    state: &'a mut ExtractState,
    last_draw: Instant,
}

impl Write for ProgressWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.state.current_written += n as u64;
        if self.last_draw.elapsed() >= REDRAW_INTERVAL {
            self.last_draw = Instant::now();
            let state = &*self.state;
            self.terminal.draw(|frame| draw_extract(frame, state))?;
        }
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Render the extraction progress screen.
fn draw_extract(frame: &mut Frame, state: &ExtractState) {
    let area = frame.area();
    let rows = Layout::vertical([
        Constraint::Length(3), // title
        Constraint::Length(3), // overall gauge
        Constraint::Length(3), // current-file gauge
        Constraint::Min(1),    // stats / status
        Constraint::Length(3), // hint
    ])
    .split(area);

    let title = Paragraph::new(state.title.clone())
        .block(Block::default().borders(Borders::ALL).title(" Extracting "));
    frame.render_widget(title, rows[0]);

    let overall = ratio(state.bytes_written(), state.bytes_total);
    frame.render_widget(
        Gauge::default()
            .block(Block::default().borders(Borders::ALL).title(" Overall "))
            .gauge_style(Style::default().fg(Color::Green))
            .ratio(overall)
            .label(format!(
                "{} / {}  ({}/{} files)",
                human_size(state.bytes_written()),
                human_size(state.bytes_total),
                state.file_index.min(state.files_total),
                state.files_total,
            )),
        rows[1],
    );

    let current = ratio(state.current_written, state.current_size);
    frame.render_widget(
        Gauge::default()
            .block(Block::default().borders(Borders::ALL).title(" Current file "))
            .gauge_style(Style::default().fg(Color::Cyan))
            .ratio(current)
            .label(state.current_name.clone()),
        rows[2],
    );

    let elapsed = state.started.elapsed().as_secs_f64();
    let rate = if elapsed > 0.0 { state.bytes_written() as f64 / elapsed } else { 0.0 };
    let remaining = state.bytes_total.saturating_sub(state.bytes_written());
    let eta = if rate > 0.0 { remaining as f64 / rate } else { f64::INFINITY };

    let status = match &state.finished {
        Some(Ok(count)) => format!("Done. Extracted {count} file(s)."),
        Some(Err(msg)) => format!("Failed: {msg}"),
        None => format!("Rate {}/s    ETA {}", human_size(rate as u64), human_duration(eta)),
    };
    frame.render_widget(
        Paragraph::new(status).block(Block::default().borders(Borders::ALL).title(" Status ")),
        rows[3],
    );

    let hint = if state.finished.is_some() {
        "press any key to return"
    } else {
        "extracting..."
    };
    frame.render_widget(
        Paragraph::new(hint).block(Block::default().borders(Borders::ALL)),
        rows[4],
    );
}

/// Clamp `done / total` into the 0.0..=1.0 range a [`Gauge`] expects.
fn ratio(done: u64, total: u64) -> f64 {
    if total == 0 {
        1.0
    } else {
        (done as f64 / total as f64).clamp(0.0, 1.0)
    }
}

/// Format a duration in seconds as `MM:SS` (or `--:--` if unknown).
fn human_duration(secs: f64) -> String {
    if !secs.is_finite() || secs < 0.0 {
        return "--:--".into();
    }
    let secs = secs as u64;
    format!("{:02}:{:02}", secs / 60, secs % 60)
}

/// Format a byte count in binary units (KiB, MiB, …).
fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

/// A rectangle `percent_x` × `percent_y` of `area`, centered.
fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let vertical = Layout::vertical([
        Constraint::Percentage((100 - percent_y) / 2),
        Constraint::Percentage(percent_y),
        Constraint::Percentage((100 - percent_y) / 2),
    ])
    .split(area);
    Layout::horizontal([
        Constraint::Percentage((100 - percent_x) / 2),
        Constraint::Percentage(percent_x),
        Constraint::Percentage((100 - percent_x) / 2),
    ])
    .split(vertical[1])[1]
}
