use std::io::{self, Write};
use std::str::FromStr;

use anyhow::{Context, Result, bail};
use jiff::Timestamp;
use owo_colors::OwoColorize;

use crate::log_list::{Log, LogList, Operator};
use crate::rfc6962::client::Client;

struct State {
    log_list: LogList,
    operator_index: Option<usize>,
    log_index: Option<usize>,
}

impl State {
    fn operator(&self) -> Result<&Operator> {
        let index = self
            .operator_index
            .context("no operator selected, select one first")?;
        Ok(&self.log_list.operators[index])
    }

    fn log(&self) -> Result<&Log> {
        let operator = self.operator()?;
        let index = self
            .log_index
            .context("no log selected, select one first")?;
        Ok(&operator.logs[index])
    }
}

enum Command {
    SelectOperator(usize),
    SelectLog(usize),
    TreeHead,
    Entries { start: u64, end: u64 },
    Help,
    Quit,
}

impl FromStr for Command {
    type Err = anyhow::Error;

    fn from_str(line: &str) -> Result<Self> {
        let mut parts = line.split_whitespace();
        let Some(name) = parts.next() else {
            bail!("empty command");
        };

        let command = match name {
            "so" => Command::SelectOperator(parse_num(parts.next(), "operator index")?),
            "sl" => Command::SelectLog(parse_num(parts.next(), "log index")?),
            "h" => Command::TreeHead,
            "e" => Command::Entries {
                start: parse_num(parts.next(), "start index")?,
                end: parse_num(parts.next(), "end index")?,
            },
            "help" | "?" => Command::Help,
            "q" => Command::Quit,
            other => bail!("unknown command: {other}"),
        };

        if parts.next().is_some() {
            bail!("unexpected extra arguments");
        }

        Ok(command)
    }
}

pub async fn launch_cli() -> Result<()> {
    println!("fetching log list...");
    let log_list = LogList::get().await.context("fetching log list")?;
    print_operators(&log_list);
    print_help();

    let mut state = State {
        log_list,
        operator_index: None,
        log_index: None,
    };
    let client = Client::new()?;

    let stdin = io::stdin();
    let mut line = String::new();
    loop {
        print!("{}", "> ".blue().bold());
        io::stdout().flush()?;

        line.clear();
        if stdin.read_line(&mut line)? == 0 {
            println!();
            break;
        }
        if line.trim().is_empty() {
            continue;
        }

        let command = match line.parse() {
            Ok(command) => command,
            Err(err) => {
                report(&err);
                continue;
            }
        };

        let result = match command {
            Command::Quit => break,
            Command::Help => {
                print_help();
                Ok(())
            }
            Command::SelectOperator(index) => select_operator(&mut state, index),
            Command::SelectLog(index) => select_log(&mut state, index),
            Command::TreeHead => tree_head(&client, &state).await,
            Command::Entries { start, end } => entries(&client, &state, start, end).await,
        };
        if let Err(err) = result {
            report(&err);
        }
    }

    Ok(())
}

fn select_operator(state: &mut State, index: usize) -> Result<()> {
    ensure_index(index, state.log_list.operators.len(), "operator")?;
    if state.operator_index != Some(index) {
        state.log_index = None;
    }
    state.operator_index = Some(index);

    let operator = &state.log_list.operators[index];
    println!("selected {} operator", operator.name.dimmed().bold());
    for (i, log) in operator.logs.iter().enumerate() {
        let description = log.common.description.clone().unwrap_or_default();
        println!(
            " {}. {} {}",
            i.green(),
            log.url,
            description.dimmed().italic()
        );
    }
    Ok(())
}

fn select_log(state: &mut State, index: usize) -> Result<()> {
    ensure_index(index, state.operator()?.logs.len(), "log")?;
    state.log_index = Some(index);

    let operator = state.operator()?;
    let log = &operator.logs[index];
    println!(
        "selected {} as list from {} operator",
        log.url.dimmed().bold(),
        operator.name.dimmed().bold()
    );
    Ok(())
}

async fn tree_head(client: &Client, state: &State) -> Result<()> {
    let log = state.log()?;
    println!(
        "fetching signed tree head for log {}",
        log.common.key.dimmed().bold(),
    );

    let sth = client
        .get_signed_tree_head(&log.url)
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

async fn entries(client: &Client, state: &State, start: u64, end: u64) -> Result<()> {
    if end < start {
        bail!("end index {end} is before start index {start}");
    }

    let log = state.log()?;
    let results = client
        .get_entries(&log.url, start, end)
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
            println!(
                "  - domains: {}",
                cert.subject_alt_names.join(", ").green().bold()
            );
            println!("  - issued at: {}", cert.not_before.green().bold());
            println!("  - expires: {}", cert.not_after.green().bold());
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

fn print_operators(log_list: &LogList) {
    println!("list of operators");

    let mut rfc6962_count = 0;
    let mut tiled_count = 0;
    for (i, operator) in log_list.operators.iter().enumerate() {
        println!(
            " {}. {} {}",
            format!("{i:2}").green(),
            operator.name,
            operator.email.join(", ").dimmed().italic()
        );
        rfc6962_count += operator.logs.len();
        tiled_count += operator.tiled_logs.len();
    }

    println!(
        "loaded log list ({}) with {} operators, {rfc6962_count} rfc6962 logs, {tiled_count} tiled logs",
        log_list.version,
        log_list.operators.len()
    );
}

fn print_help() {
    for (name, args, description) in [
        ("so", "<index>", "select operator"),
        ("sl", "<index>", "select log"),
        ("h", "", "signed tree head"),
        ("e", "<start> <end>", "get entries"),
        ("help", "", "show commands"),
        ("q", "", "quit"),
    ] {
        println!(
            "  {} {} {}",
            format!("{name:<4}").blue().bold(),
            format!("{args:<14}").dimmed(),
            description
        );
    }
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

fn ensure_index(index: usize, len: usize, what: &str) -> Result<()> {
    if index >= len {
        bail!("{what} index {index} is out of range ({len} available)");
    }
    Ok(())
}

fn report(err: &anyhow::Error) {
    println!("{}", err.red());
}
