//! `amber-shield-scan` - headless CLI entry point for the Amber Shield
//! GitHub Action. Runs Trivy + GitLeaks over a path, builds the Amber
//! Shield heatmap on top of their findings, writes a JSON (and optionally
//! SARIF) report, prints a human-readable summary, and exits non-zero if
//! anything at or above `--fail-on` was found - so a workflow step can
//! just do `amber-shield-scan . --fail-on high` and let the exit code
//! gate the job.

mod codemap;
mod security;

use security::{run_gitleaks, run_trivy, SecretFinding, Vulnerability};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

struct Args {
    path: PathBuf,
    fail_on: Severity,
    format: Format,
    report_path: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Severity {
    None = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

impl Severity {
    fn parse(s: &str) -> Option<Self> {
        Some(match s.to_ascii_lowercase().as_str() {
            "none" => Severity::None,
            "low" => Severity::Low,
            "medium" | "unknown" => Severity::Medium,
            "high" => Severity::High,
            "critical" => Severity::Critical,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy)]
enum Format {
    Json,
    Sarif,
}

fn print_usage() {
    eprintln!(
        "amber-shield-scan [PATH] [--fail-on none|low|medium|high|critical] [--format json|sarif] [--report-path FILE]\n\n\
         Environment overrides: AMBER_TRIVY_BIN, AMBER_GITLEAKS_BIN (point at pinned binaries instead of PATH lookup).\n\n\
         Also accepts the three positional args the GitHub Action passes: PATH FAIL_ON FORMAT."
    );
}

fn parse_args() -> anyhow::Result<Args> {
    let raw: Vec<String> = env::args().skip(1).collect();

    if raw.iter().any(|a| a == "-h" || a == "--help") {
        print_usage();
        std::process::exit(0);
    }

    let mut path = PathBuf::from(".");
    let mut fail_on = Severity::Critical;
    let mut format = Format::Json;
    let mut report_path: Option<PathBuf> = None;
    let mut positional_index = 0usize;

    let mut i = 0;
    while i < raw.len() {
        let arg = &raw[i];
        match arg.as_str() {
            "--fail-on" => {
                let v = raw.get(i + 1).ok_or_else(|| anyhow::anyhow!("--fail-on needs a value"))?;
                fail_on = Severity::parse(v).ok_or_else(|| anyhow::anyhow!("invalid --fail-on value: {v}"))?;
                i += 2;
            }
            "--format" => {
                let v = raw.get(i + 1).ok_or_else(|| anyhow::anyhow!("--format needs a value"))?;
                format = match v.to_ascii_lowercase().as_str() {
                    "json" => Format::Json,
                    "sarif" => Format::Sarif,
                    _ => anyhow::bail!("invalid --format value: {v} (expected json or sarif)"),
                };
                i += 2;
            }
            "--report-path" => {
                let v = raw.get(i + 1).ok_or_else(|| anyhow::anyhow!("--report-path needs a value"))?;
                if !v.is_empty() {
                    report_path = Some(PathBuf::from(v));
                }
                i += 2;
            }
            other => {
                // Positional args, matching how the Docker action invokes us:
                // 0 = path, 1 = fail-on, 2 = format. Empty strings (an unset
                // action input passed through as "") mean "use the default".
                match positional_index {
                    0 => {
                        if !other.is_empty() {
                            path = PathBuf::from(other);
                        }
                    }
                    1 => {
                        if !other.is_empty() {
                            fail_on = Severity::parse(other)
                                .ok_or_else(|| anyhow::anyhow!("invalid fail-on value: {other}"))?;
                        }
                    }
                    2 => {
                        if !other.is_empty() {
                            format = match other.to_ascii_lowercase().as_str() {
                                "json" => Format::Json,
                                "sarif" => Format::Sarif,
                                _ => anyhow::bail!("invalid format value: {other} (expected json or sarif)"),
                            };
                        }
                    }
                    _ => anyhow::bail!("unexpected extra argument: {other}"),
                }
                positional_index += 1;
                i += 1;
            }
        }
    }

    let report_path = report_path.unwrap_or_else(|| match format {
        Format::Json => PathBuf::from("amber-shield-report.json"),
        Format::Sarif => PathBuf::from("amber-shield-report.sarif"),
    });

    Ok(Args { path, fail_on, format, report_path })
}

fn trivy_severity(v: &Vulnerability) -> Severity {
    Severity::parse(&v.severity).unwrap_or(Severity::Medium)
}

/// A leaked secret is treated as Critical regardless of what GitLeaks'
/// rule metadata says - there is no "low severity" live credential.
fn secret_severity(_s: &SecretFinding) -> Severity {
    Severity::Critical
}

fn worst_severity(vulns: &[Vulnerability], secrets: &[SecretFinding]) -> Severity {
    let worst_vuln = vulns.iter().map(trivy_severity).max().unwrap_or(Severity::None);
    let worst_secret = secrets.iter().map(secret_severity).max().unwrap_or(Severity::None);
    worst_vuln.max(worst_secret)
}

fn write_json_report(
    path: &Path,
    heatmap: &[codemap::FileHeat],
    vulns: &[Vulnerability],
    secrets: &[SecretFinding],
) -> anyhow::Result<()> {
    let report = serde_json::json!({
        "scanner": "amber-shield-scan",
        "vulnerabilities": vulns,
        "secrets": secrets,
        "heatmap": heatmap,
    });
    fs::write(path, serde_json::to_vec_pretty(&report)?)?;
    Ok(())
}

fn sarif_severity_level(sev: Severity) -> &'static str {
    match sev {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::None => "note",
    }
}

/// Minimal but valid SARIF 2.1.0, enough for `github/codeql-action/upload-sarif`
/// to render results in the repo's Security tab. Not a full-fidelity Trivy/
/// GitLeaks SARIF converter - just what's needed to surface findings there.
fn write_sarif_report(
    path: &Path,
    vulns: &[Vulnerability],
    secrets: &[SecretFinding],
) -> anyhow::Result<()> {
    let mut results = Vec::new();

    for v in vulns {
        let sev = trivy_severity(v);
        results.push(serde_json::json!({
            "ruleId": v.id,
            "level": sarif_severity_level(sev),
            "message": { "text": v.title.clone().unwrap_or_else(|| format!("{} in {}", v.id, v.pkg_name)) },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": { "uri": v.target }
                }
            }]
        }));
    }

    for s in secrets {
        results.push(serde_json::json!({
            "ruleId": s.rule_id,
            "level": "error",
            "message": { "text": s.description.clone().unwrap_or_else(|| "potential secret detected".to_string()) },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": { "uri": s.file },
                    "region": { "startLine": s.start_line.max(1) }
                }
            }]
        }));
    }

    let sarif = serde_json::json!({
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "amber-shield-scan",
                    "informationUri": "https://github.com/aurora-ember-bio-lab/amber-shield-scan-action",
                    "version": env!("CARGO_PKG_VERSION"),
                }
            },
            "results": results,
        }]
    });

    fs::write(path, serde_json::to_vec_pretty(&sarif)?)?;
    Ok(())
}

fn emit_github_output(name: &str, value: &str) {
    if let Ok(path) = env::var("GITHUB_OUTPUT") {
        use std::io::Write;
        if let Ok(mut f) = fs::OpenOptions::new().create(true).append(true).open(path) {
            let _ = writeln!(f, "{name}={value}");
        }
    }
}

fn run() -> anyhow::Result<bool> {
    let args = parse_args()?;

    if !args.path.exists() {
        anyhow::bail!("path does not exist: {}", args.path.display());
    }

    let vulns = match run_trivy(&args.path) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("warning: trivy scan failed, continuing with 0 dependency findings: {e}");
            Vec::new()
        }
    };
    let secrets = match run_gitleaks(&args.path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("warning: gitleaks scan failed, continuing with 0 secret findings: {e}");
            Vec::new()
        }
    };

    let heatmap = codemap::build_heatmap(&args.path, &vulns, &secrets)?;

    match args.format {
        Format::Json => write_json_report(&args.report_path, &heatmap, &vulns, &secrets)?,
        Format::Sarif => write_sarif_report(&args.report_path, &vulns, &secrets)?,
    }

    let vulnerable_files = heatmap
        .iter()
        .filter(|f| f.category == codemap::HeatCategory::Vulnerable)
        .count();

    println!("Amber Shield scan of {}", args.path.display());
    println!("  files scanned:        {}", heatmap.len());
    println!("  vulnerable files:     {vulnerable_files}");
    println!("  dependency findings:  {}", vulns.len());
    println!("  secret findings:      {}", secrets.len());
    println!("  report written to:    {}", args.report_path.display());

    if !heatmap.is_empty() {
        println!("\nTop flagged files:");
        for f in heatmap.iter().filter(|f| f.score > 0).take(10) {
            println!("  [{:>10?}] score {:>4}  {}", f.category, f.score, f.path);
        }
    }

    emit_github_output("report-path", &args.report_path.display().to_string());
    emit_github_output("vulnerable-files", &vulnerable_files.to_string());
    emit_github_output("dependency-findings", &vulns.len().to_string());
    emit_github_output("secret-findings", &secrets.len().to_string());

    let worst = worst_severity(&vulns, &secrets);
    let should_fail = args.fail_on != Severity::None && worst >= args.fail_on && worst != Severity::None;

    if should_fail {
        eprintln!(
            "\nAmber Shield: failing - worst finding severity is at or above --fail-on ({:?})",
            args.fail_on
        );
    }

    Ok(!should_fail)
}

fn main() -> ExitCode {
    match run() {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(e) => {
            eprintln!("amber-shield-scan: error: {e}");
            ExitCode::from(2)
        }
    }
}
