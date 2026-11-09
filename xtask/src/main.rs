#![forbid(unsafe_code)]

//! `cargo xtask download-geodb` fetches the current DB-IP Lite MMDB files.
//!
//! The files are CC BY 4.0 and are not committed. City Lite is the geolocation
//! source. ASN Lite is the autonomous-system source. Both are MaxMind DB files.

use anyhow::{Context, Result, bail};
use chrono::{Datelike, NaiveDate, Utc};
use std::env;
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        Some("download-geodb") => download_geodb(args.collect()),
        _ => {
            eprintln!("usage: cargo xtask download-geodb [--out-dir DIR] [--month YYYY-MM]");
            std::process::exit(2);
        }
    }
}

fn download_geodb(args: Vec<String>) -> Result<()> {
    let mut out_dir = PathBuf::from("data");
    let mut month: Option<NaiveDate> = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--out-dir" => {
                index += 1;
                out_dir = PathBuf::from(args.get(index).context("--out-dir needs a path")?);
            }
            "--month" => {
                index += 1;
                let text = args.get(index).context("--month needs YYYY-MM")?;
                month = Some(parse_month(text)?);
            }
            other => bail!("unknown argument {other}"),
        }
        index += 1;
    }

    fs::create_dir_all(&out_dir)?;
    let primary = month.unwrap_or_else(|| Utc::now().date_naive());
    let months = match month {
        Some(pinned) => vec![pinned],
        None => vec![month_start(primary), previous_month(primary)],
    };

    let mut last_err = None;
    for candidate in months {
        match download_month(&out_dir, candidate) {
            Ok(()) => {
                println!("IP Geolocation by DB-IP (https://db-ip.com), licensed under CC BY 4.0.");
                println!(
                    "Saved under {}. Do not commit these files.",
                    out_dir.display()
                );
                return Ok(());
            }
            Err(err) => {
                eprintln!("month {}: {err:#}", candidate.format("%Y-%m"));
                last_err = Some(err);
            }
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("no month was attempted")))
}

fn download_month(out_dir: &Path, month: NaiveDate) -> Result<()> {
    let stamp = month.format("%Y-%m");
    download_one(
        &format!("https://download.db-ip.com/free/dbip-city-lite-{stamp}.mmdb.gz"),
        &out_dir.join("dbip-city-lite.mmdb"),
    )?;
    download_one(
        &format!("https://download.db-ip.com/free/dbip-asn-lite-{stamp}.mmdb.gz"),
        &out_dir.join("dbip-asn-lite.mmdb"),
    )?;
    Ok(())
}

fn download_one(url: &str, dest: &Path) -> Result<()> {
    let gz = dest.with_extension("mmdb.gz");
    let status = Command::new("curl")
        .args(["-fsSL", "--retry", "3", "--retry-delay", "2", "-o"])
        .arg(&gz)
        .arg(url)
        .status()
        .with_context(|| format!("run curl for {url}"))?;
    if !status.success() {
        let _ = fs::remove_file(&gz);
        bail!("curl exited {status} for {url}");
    }
    let output = File::create(dest).with_context(|| format!("create {}", dest.display()))?;
    let status = Command::new("gzip")
        .args(["-dc"])
        .arg(&gz)
        .stdout(output)
        .status()
        .with_context(|| format!("decompress {}", gz.display()))?;
    let _ = fs::remove_file(&gz);
    if !status.success() {
        bail!("gzip exited {status} while decompressing {url}");
    }
    let len = fs::metadata(dest)?.len();
    if len < 1024 {
        bail!("{} is unexpectedly small ({len} bytes)", dest.display());
    }
    println!("wrote {} ({} bytes) from {url}", dest.display(), len);
    Ok(())
}

fn parse_month(text: &str) -> Result<NaiveDate> {
    let mut parts = text.split('-');
    let year: i32 = parts
        .next()
        .context("year")?
        .parse()
        .context("year is not a number")?;
    let month: u32 = parts
        .next()
        .context("month")?
        .parse()
        .context("month is not a number")?;
    NaiveDate::from_ymd_opt(year, month, 1).context("month is out of range")
}

fn month_start(date: NaiveDate) -> NaiveDate {
    NaiveDate::from_ymd_opt(date.year(), date.month(), 1).expect("valid month")
}

fn previous_month(date: NaiveDate) -> NaiveDate {
    let start = month_start(date);
    if start.month() == 1 {
        NaiveDate::from_ymd_opt(start.year() - 1, 12, 1).expect("december")
    } else {
        NaiveDate::from_ymd_opt(start.year(), start.month() - 1, 1).expect("previous month")
    }
}
