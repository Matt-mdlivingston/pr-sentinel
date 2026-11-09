//! The generate → score path the README tells a person to run.

use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_pr-sentinel")
}

#[test]
fn generate_then_score_json_explains_an_alert() {
    let dir = tempfile::tempdir().unwrap();
    let events = dir.path().join("events.jsonl");
    let fixture = dir.path().join("geo.json");
    let generated = Command::new(bin())
        .args([
            "generate",
            "--seed",
            "7",
            "--users",
            "8",
            "--days",
            "3",
            "--events",
            events.to_str().unwrap(),
            "--geo-fixture",
            fixture.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        generated.status.success(),
        "generate failed: {}",
        String::from_utf8_lossy(&generated.stderr)
    );

    let scored = Command::new(bin())
        .args([
            "score",
            "--events",
            events.to_str().unwrap(),
            "--geo-fixture",
            fixture.to_str().unwrap(),
            "--format",
            "json",
            "--min-score",
            "60",
        ])
        .output()
        .unwrap();
    assert!(
        scored.status.success(),
        "score failed: {}",
        String::from_utf8_lossy(&scored.stderr)
    );
    let stdout = String::from_utf8(scored.stdout).unwrap();
    let mut alerts = 0_usize;
    for line in stdout.lines() {
        let value: serde_json::Value = serde_json::from_str(line).unwrap();
        let score = value["score"].as_u64().unwrap();
        assert!(score >= 60);
        let contributions = value["contributions"].as_array().unwrap();
        assert!(!contributions.is_empty());
        assert!(contributions.iter().all(|contribution| {
            contribution["reason"]
                .as_str()
                .is_some_and(|reason| !reason.is_empty())
        }));
        alerts += 1;
    }
    assert!(
        alerts >= 1,
        "expected at least one alert, stderr {}",
        String::from_utf8_lossy(&scored.stderr)
    );
}
