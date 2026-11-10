use std::io::{self, Write};
use std::str::FromStr;

use anyhow::{Context, Result, bail};
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use jiff::Timestamp;
use owo_colors::OwoColorize;

use crate::log_list::{Log, LogList, Operator};
use crate::rfc6962::client::Client;

struct State {
    log_list: LogList,
    operator_index: usize,
    log_index: usize,
}

impl State {
    fn operator(&self) -> &Operator {
        &self.log_list.operators[self.operator_index]
    }

    fn log(&self) -> &Log {
        &self.operator().logs[self.log_index]
    }
}

enum Action {
    Operator,
    Log,
    TreeHead,
    Entries,
    Help,
    Quit,
    Unknown(char),
}

pub async fn launch_cli() -> Result<()> {
    print_banner();
    println!("fetching log list...");
    let log_list = LogList::get().await.context("fetching log list")?;
    let operator_index = log_list
        .operators
        .iter()
        .position(|operator| !operator.logs.is_empty())
        .context("log list has no rfc6962 logs")?;
    let mut state = State {
        log_list,
        operator_index,
        log_index: 0,
    };
    let client = Client::new()?;

    print_operators(&state);
    print_logs(&state);
    print_help();
    print_status(&state);

    loop {
        match read_action()? {
            Action::Quit => break,
            Action::Help => print_help(),
            Action::Operator => {
                print_operators(&state);
                if let Some(index) = prompt(read_index("operator")) {
                    report_err(select_operator(&mut state, index));
                }
            }
            Action::Log => {
                print_logs(&state);
                if let Some(index) = prompt(read_index("log")) {
                    report_err(select_log(&mut state, index));
                }
            }
            Action::TreeHead => {
                let log = state.log();
                report_err(tree_head(&client, &log.url, &log.common.key).await);
            }
            Action::Entries => {
                if let Some((start, end)) = prompt(read_range()) {
                    let url = state.log().url.clone();
                    report_err(entries(&client, &url, start, end).await);
                }
            }
            Action::Unknown(key) => {
                println!("{}", format!("{key} is not a command").red());
            }
        }
        print_status(&state);
    }

    Ok(())
}

fn print_banner() {
    println!();
    for (i, step) in ["·", "·", "·"].iter().enumerate() {
        println!("{:width$}{}", "", step.dimmed(), width = i * 2);
    }
    for line in [
        " ███ ███   ██   ██  ███ ",
        "█    █  █ █  █ █  █ █  █",
        " ██  ███  █  █ █  █ ███ ",
        "   █ █    █  █ █  █ █ █ ",
        "███  █     ██   ██  █  █",
    ] {
        println!("{}", line.green().bold());
    }
    println!("{}", "·   ·   ·   ·   ·".dimmed());
    println!("{}", "certificate transparency explorer".dimmed().italic());
    println!();
}

fn print_operators(state: &State) {
    println!("operators");
    let mut rfc6962_count = 0;
    let mut tiled_count = 0;
    for (i, operator) in state.log_list.operators.iter().enumerate() {
        let index = format!("{i:2}");
        let index = if i == state.operator_index {
            index.green().bold().to_string()
        } else {
            index.bold().to_string()
        };
        println!(
            " {index}. {} {}",
            operator.name,
            operator.email.join(", ").dimmed().italic()
        );
        rfc6962_count += operator.logs.len();
        tiled_count += operator.tiled_logs.len();
    }
    println!(
        "loaded log list ({}) with {} operators, {rfc6962_count} rfc6962 logs, {tiled_count} tiled logs\n",
        format!("v{}", state.log_list.version).bold(),
        state.log_list.operators.len()
    );
}

fn print_logs(state: &State) {
    let operator = state.operator();
    println!("logs for {}", operator.name.dimmed().bold());
    for (i, log) in operator.logs.iter().enumerate() {
        let index = format!("{i:2}");
        let index = if i == state.log_index {
            index.green().bold().to_string()
        } else {
            index.bold().to_string()
        };
        let description = log.common.description.as_deref().unwrap_or("");
        println!(" {index}. {} {}", log.url, description.dimmed().italic());
    }
}

fn print_selected_log(state: &State) {
    println!(
        "selected {} from {}",
        state.log().url.dimmed().bold(),
        state.operator().name.dimmed().bold()
    );
}

fn print_status(state: &State) {
    println!(
        "{} {} / {}",
        ">".blue().bold(),
        state.operator().name.green().bold(),
        log_label(&state.log().url).bright_green()
    );
}

fn print_help() {
    for (key, description) in [
        ("o", "select operator"),
        ("l", "select log"),
        ("h", "signed tree head"),
        ("e", "entries, then start and end"),
        ("?", "show commands"),
        ("q", "quit"),
    ] {
        println!("  {}  {}", format!("{key:<5}").blue().bold(), description);
    }
}

async fn tree_head(client: &Client, url: &str, key: &str) -> Result<()> {
    println!("fetching signed tree head for log {}", key.dimmed().bold());

    let sth = client
        .get_signed_tree_head(url)
        .await
        .context("unable to retrieve the signed tree head")?;
    let changed_at = Timestamp::from_millisecond(sth.timestamp)
        .context("signed tree head has an invalid timestamp")?;

    println!(
        "tree size of {} {} - last change at {changed_at}",
        sth.tree_size.bold(),
        sth.tree_head_signature.italic().dimmed(),
    );
    Ok(())
}

async fn entries(client: &Client, url: &str, start: u64, end: u64) -> Result<()> {
    if end < start {
        bail!("end index {end} is before start index {start}");
    }

    let results = client
        .get_entries(url, start, end)
        .await
        .context("unable to retrieve entries")?;

    println!("fetched {} entries", results.len());

    let mut domains = Vec::new();
    for (offset, result) in results.into_iter().enumerate() {
        let index = start + offset as u64;
        let entry = match result {
            Ok(entry) => entry,
            Err(err) => {
                println!("{} {}", index.bold().dimmed(), err.red());
                continue;
            }
        };

        println!(
            "{}. {} - {} certificates",
            index.green().bold(),
            entry.timestamp,
            entry.certificates.0.len()
        );
        for cert in &entry.certificates.0 {
            println!("  {}", cert.serial.dimmed());
            println!("  - subject: {}", cert.subject.purple().bold());
            println!("  - issuer: {}", cert.issuer.cyan().bold());
            println!(
                "  - domains: {}",
                cert.subject_alt_names.join(", ").green().bold()
            );
            println!("  - issued at: {}", cert.not_before.green().bold());
            println!("  - expires: {}", cert.not_after.green().bold());
            println!("  - signature: {}", cert.signature_algorithm.dimmed());
        }

        domains.extend(
            entry
                .certificates
                .0
                .into_iter()
                .flat_map(|cert| cert.subject_alt_names),
        );
    }

    println!("related domains: {}", domains.join(", ").green().bold());
    Ok(())
}

fn read_action() -> Result<Action> {
    let _raw = RawMode::enter()?;
    loop {
        let Event::Key(key) = event::read()? else {
            continue;
        };
        if key.kind != KeyEventKind::Press {
            continue;
        }
        if let Some(action) = action(key) {
            return Ok(action);
        }
    }
}

fn action(key: KeyEvent) -> Option<Action> {
    if key.modifiers.contains(KeyModifiers::CONTROL) {
        return match key.code {
            KeyCode::Char('c' | 'd') => Some(Action::Quit),
            _ => None,
        };
    }
    Some(match key.code {
        KeyCode::Char('o') => Action::Operator,
        KeyCode::Char('l') => Action::Log,
        KeyCode::Char('h') => Action::TreeHead,
        KeyCode::Char('e') => Action::Entries,
        KeyCode::Char('?') => Action::Help,
        KeyCode::Char('q') => Action::Quit,
        KeyCode::Char(other) => Action::Unknown(other),
        _ => return None,
    })
}

fn select_operator(state: &mut State, index: usize) -> Result<()> {
    let operator = state
        .log_list
        .operators
        .get(index)
        .with_context(|| format!("operator index {index} is out of range"))?;
    if operator.logs.is_empty() {
        bail!("{} has no rfc6962 logs", operator.name);
    }
    if index != state.operator_index {
        state.log_index = 0;
    }
    state.operator_index = index;
    print_logs(state);
    Ok(())
}

fn select_log(state: &mut State, index: usize) -> Result<()> {
    let len = state.operator().logs.len();
    if index >= len {
        bail!("log index {index} is out of range ({len} available)");
    }
    state.log_index = index;
    print_selected_log(state);
    Ok(())
}

fn read_index(what: &str) -> Result<Option<usize>> {
    let Some(fields) = read_fields(what)? else {
        return Ok(None);
    };
    let mut parts = fields.iter().map(String::as_str);
    let index = parse_num(parts.next(), &format!("{what} index"))?;
    if parts.next().is_some() {
        bail!("unexpected extra arguments");
    }
    Ok(Some(index))
}

fn read_range() -> Result<Option<(u64, u64)>> {
    let Some(fields) = read_fields("start end")? else {
        return Ok(None);
    };
    let mut parts = fields.iter().map(String::as_str);
    let start = parse_num(parts.next(), "start index")?;
    let end = parse_num(parts.next(), "end index")?;
    if parts.next().is_some() {
        bail!("unexpected extra arguments");
    }
    Ok(Some((start, end)))
}

fn read_fields(prompt_text: &str) -> Result<Option<Vec<String>>> {
    print!("{} ", prompt_text.blue().bold());
    io::stdout().flush()?;
    let mut line = String::new();
    if io::stdin().read_line(&mut line)? == 0 {
        println!();
        return Ok(None);
    }
    Ok(Some(line.split_whitespace().map(str::to_string).collect()))
}

fn parse_num<T>(raw: Option<&str>, what: &str) -> Result<T>
where
    T: FromStr,
    T::Err: std::error::Error + Send + Sync + 'static,
{
    let raw = raw.with_context(|| format!("missing {what}"))?;
    raw.parse()
        .with_context(|| format!("{raw} is not a valid {what}"))
}

fn prompt<T>(result: Result<Option<T>>) -> Option<T> {
    match result {
        Ok(value) => value,
        Err(err) => {
            report(&err);
            None
        }
    }
}

fn report_err(result: Result<()>) {
    if let Err(err) = result {
        report(&err);
    }
}

fn log_label(url: &str) -> &str {
    url.trim_end_matches('/')
        .rsplit('/')
        .next()
        .filter(|label| !label.is_empty())
        .unwrap_or(url)
}

fn report(err: &anyhow::Error) {
    println!("{}", err.red());
}

struct RawMode;

impl RawMode {
    fn enter() -> Result<Self> {
        enable_raw_mode()?;
        Ok(Self)
    }
}

impl Drop for RawMode {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
    }
}
