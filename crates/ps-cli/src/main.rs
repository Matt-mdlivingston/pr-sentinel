#![forbid(unsafe_code)]

//! `pr-sentinel` command line.
//!
//! `generate` writes a seeded JSONL file and a geo fixture. `score` reads
//! JSONL, enriches each address, and prints a score with the signals that
//! produced it. Scoring always walks every event so history stays coherent;
//! `--min-score` only filters what is printed.

use anyhow::{Context, Result, bail};
use chrono::SecondsFormat;
use clap::{Parser, Subcommand, ValueEnum};
use ps_core::{IpLookup, LoginEvent, RiskScore};
use ps_engine::{Engine, Rules, default_rules};
use ps_enrich::{DbIpEnricher, FallbackLookup, FixtureLookup, GeoFixture};
use ps_gen::{GenerateOptions, generate};
use serde::Serialize;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::PathBuf;

mod format;

#[derive(Debug, Parser)]
#[command(
    name = "pr-sentinel",
    version,
    about = "Score suspicious logins by combining weak signals"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Score JSONL login events and print the evidence behind each score.
    Score(ScoreArgs),
    /// Write a seeded synthetic dataset and the geo fixture it must be scored with.
    Generate(GenerateArgs),
}

#[derive(Debug, clap::Args)]
struct ScoreArgs {
    /// JSONL file of login events. A `labels` field, if present, is ignored.
    #[arg(long)]
    events: PathBuf,
    /// Rules TOML. Defaults to the built-in policy.
    #[arg(long)]
    rules: Option<PathBuf>,
    /// DB-IP City Lite MMDB. Must be paired with `--asn-db`.
    #[arg(long)]
    city_db: Option<PathBuf>,
    /// DB-IP ASN Lite MMDB. Must be paired with `--city-db`.
    #[arg(long)]
    asn_db: Option<PathBuf>,
    /// JSON fixture used for addresses the database does not contain.
    #[arg(long)]
    geo_fixture: Option<PathBuf>,
    /// `text` (default) or `json` (one object per line).
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,
    /// Only print events whose score is at least this value.
    ///
    /// Events below the cutoff are still scored. Dropping them from the walk
    /// would change history for the events that follow.
    #[arg(long, default_value_t = 0)]
    min_score: u8,
}

#[derive(Debug, clap::Args)]
struct GenerateArgs {
    /// Mixer seed.
    #[arg(long, default_value_t = 42)]
    seed: u64,
    /// Where to write JSONL events.
    #[arg(long)]
    events: PathBuf,
    /// Where to write the geo fixture JSON.
    #[arg(long)]
    geo_fixture: PathBuf,
    /// Home users. Each gets a unique documentation address.
    #[arg(long, default_value_t = 20)]
    users: usize,
    /// Days of ordinary traffic.
    #[arg(long, default_value_t = 5)]
    days: u16,
    /// Tenant id stamped on every event.
    #[arg(long, default_value = "demo")]
    tenant: String,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
}

impl std::fmt::Display for OutputFormat {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Text => "text",
            Self::Json => "json",
        })
    }
}

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    match Cli::parse().command {
        Command::Score(args) => score(args),
        Command::Generate(args) => generate_cmd(args),
    }
}

fn generate_cmd(args: GenerateArgs) -> Result<()> {
    let options = GenerateOptions {
        seed: args.seed,
        users: args.users,
        days: args.days,
        tenant_id: args.tenant,
        ..GenerateOptions::default()
    };
    let dataset = generate(&options)?;
    let summary = dataset.summary();
    write_file(&args.events, dataset.to_jsonl()?.as_bytes())?;
    write_file(
        &args.geo_fixture,
        format!("{}\n", dataset.fixture_json()?).as_bytes(),
    )?;
    eprintln!(
        "wrote {} events ({} impossible_travel, {} credential_stuffing, {} ordinary) to {}",
        summary.events,
        summary.impossible_travel,
        summary.credential_stuffing,
        summary.ordinary,
        args.events.display()
    );
    eprintln!(
        "wrote geo fixture with {} addresses to {}",
        summary.fixture_ips,
        args.geo_fixture.display()
    );
    Ok(())
}

fn score(args: ScoreArgs) -> Result<()> {
    let rules = load_rules(args.rules.as_ref())?;
    let lookup = build_lookup(&args)?;
    let events = read_events(&args.events)?;
    let located = events
        .iter()
        .filter(|event| lookup.lookup(event.ip).is_located())
        .count();
    if located == 0 && !events.is_empty() {
        eprintln!(
            "warning: no event had coordinates. Impossible travel and new-ASN cannot fire. Synthetic files need --geo-fixture."
        );
    }
    let mut engine = Engine::new(rules)?;
    let stdout = std::io::stdout();
    let mut out = BufWriter::new(stdout.lock());
    let mut shown = 0_usize;
    for event in &events {
        let info = lookup.lookup(event.ip);
        let scored = engine.score(event, &info)?;
        if scored.score < args.min_score {
            continue;
        }
        shown += 1;
        match args.format {
            OutputFormat::Text => write!(out, "{}", format::text(event, &scored))?,
            OutputFormat::Json => {
                let line = serde_json::to_string(&json_score(event, &scored))?;
                writeln!(out, "{line}")?;
            }
        }
    }
    out.flush()?;
    eprintln!(
        "scored {} events, {} with score >= {}",
        events.len(),
        shown,
        args.min_score
    );
    Ok(())
}

fn load_rules(path: Option<&PathBuf>) -> Result<Rules> {
    match path {
        Some(path) => {
            let text = fs::read_to_string(path)
                .with_context(|| format!("read rules {}", path.display()))?;
            Ok(Rules::from_toml(&text)?)
        }
        None => Ok(default_rules()?),
    }
}

fn build_lookup(args: &ScoreArgs) -> Result<Box<dyn IpLookup>> {
    match (&args.city_db, &args.asn_db, &args.geo_fixture) {
        (None, None, None) => {
            bail!("pass --geo-fixture, or both --city-db and --asn-db");
        }
        (Some(_), None, _) | (None, Some(_), _) => {
            bail!("--city-db and --asn-db must be passed together");
        }
        (None, None, Some(path)) => {
            let fixture = load_fixture(path)?;
            Ok(Box::new(FixtureLookup::from_fixture(&fixture)?))
        }
        (Some(city), Some(asn), None) => {
            let enricher = DbIpEnricher::open(city, asn)?;
            let (city_type, asn_type) = enricher.database_types();
            eprintln!("enrichment: {city_type} + {asn_type}");
            Ok(Box::new(enricher))
        }
        (Some(city), Some(asn), Some(path)) => {
            let enricher = DbIpEnricher::open(city, asn)?;
            let (city_type, asn_type) = enricher.database_types();
            let fixture = load_fixture(path)?;
            eprintln!(
                "enrichment: {city_type} + {asn_type}, fixture fallback ({} addresses)",
                fixture.ips.len()
            );
            Ok(Box::new(FallbackLookup::new(
                enricher,
                FixtureLookup::from_fixture(&fixture)?,
            )))
        }
    }
}

fn load_fixture(path: &PathBuf) -> Result<GeoFixture> {
    let file = File::open(path).with_context(|| format!("open geo fixture {}", path.display()))?;
    Ok(GeoFixture::from_reader(file)?)
}

fn read_events(path: &PathBuf) -> Result<Vec<LoginEvent>> {
    let file = File::open(path).with_context(|| format!("open events {}", path.display()))?;
    let reader = BufReader::new(file);
    let mut events = Vec::new();
    for (index, line) in reader.lines().enumerate() {
        let line = line.with_context(|| format!("read {} line {}", path.display(), index + 1))?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let mut value: serde_json::Value = serde_json::from_str(trimmed)
            .with_context(|| format!("{} line {} is not JSON", path.display(), index + 1))?;
        if let Some(map) = value.as_object_mut() {
            map.remove("labels");
        }
        let event: LoginEvent = serde_json::from_value(value).with_context(|| {
            format!("{} line {} is not a login event", path.display(), index + 1)
        })?;
        events.push(event);
    }
    let original: Vec<_> = events
        .iter()
        .map(|event| event.event_id.as_str().to_owned())
        .collect();
    events.sort_by(|left, right| {
        left.timestamp
            .cmp(&right.timestamp)
            .then_with(|| left.event_id.cmp(&right.event_id))
    });
    let sorted: Vec<_> = events
        .iter()
        .map(|event| event.event_id.as_str().to_owned())
        .collect();
    if sorted != original {
        eprintln!("sorted {} events into timestamp order", events.len());
    }
    Ok(events)
}

fn write_file(path: &PathBuf, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .with_context(|| format!("create directory {}", parent.display()))?;
        }
    }
    fs::write(path, bytes).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

#[derive(Serialize)]
struct JsonScore {
    event_id: String,
    user_id: String,
    tenant_id: String,
    timestamp: String,
    ip: String,
    success: bool,
    score: u8,
    probability: f64,
    prior_log_odds: f64,
    total_log_odds: f64,
    prior_points: u8,
    contributions: Vec<JsonContribution>,
}

#[derive(Serialize)]
struct JsonContribution {
    signal: String,
    log_odds: f64,
    points: i16,
    reason: String,
}

fn json_score(event: &LoginEvent, score: &RiskScore) -> JsonScore {
    JsonScore {
        event_id: event.event_id.to_string(),
        user_id: event.user_id.to_string(),
        tenant_id: event.tenant_id.to_string(),
        timestamp: event.timestamp.to_rfc3339_opts(SecondsFormat::Secs, true),
        ip: event.ip.to_string(),
        success: event.success,
        score: score.score,
        probability: score.probability,
        prior_log_odds: score.prior_log_odds,
        total_log_odds: score.total_log_odds,
        prior_points: score.prior_points,
        contributions: score
            .contributions
            .iter()
            .map(|contribution| JsonContribution {
                signal: contribution.id.to_string(),
                log_odds: contribution.log_odds,
                points: contribution.points,
                reason: contribution.reason.clone(),
            })
            .collect(),
    }
}
