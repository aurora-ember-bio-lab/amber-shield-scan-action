//! Wraps `gitleaks detect --report-format json --report-path -` (secret
//! scanning). Exits non-zero when leaks are found, which is Gitleaks'
//! documented behavior, not an error - that's handled explicitly below
//! rather than treated as a scanner failure.

use super::{locate, Result, ScannerError};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::process::Command;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretFinding {
    pub rule_id: String,
    pub file: String,
    pub start_line: u32,
    pub commit: Option<String>,
    pub description: Option<String>,
}

#[derive(Deserialize)]
struct GitleaksFinding {
    #[serde(rename = "RuleID")]
    rule_id: String,
    #[serde(rename = "File")]
    file: String,
    #[serde(rename = "StartLine")]
    start_line: u32,
    #[serde(rename = "Commit")]
    commit: Option<String>,
    #[serde(rename = "Description")]
    description: Option<String>,
}

pub fn run_gitleaks(repo_path: &Path) -> Result<Vec<SecretFinding>> {
    let bin = locate("gitleaks", "AMBER_GITLEAKS_BIN")?;

    // `--no-git`: scan the working tree as plain files rather than git
    // history. On a checkout with no `.git` (e.g. `actions/checkout` with
    // `fetch-depth: 0` disabled, or a scan of a subdirectory), gitleaks'
    // default `detect` mode would quietly report zero findings instead of
    // erroring - working-tree scanning also matches what the heatmap shows
    // (current files on disk, not git history).
    let output = Command::new(bin)
        .args(["detect", "--no-git", "--report-format", "json", "--report-path", "-", "--exit-code", "0"])
        .arg("--source")
        .arg(repo_path)
        .output()?;

    if !output.status.success() {
        return Err(ScannerError::Io(std::io::Error::other(format!(
            "gitleaks exited with {:?}: {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        ))));
    }

    if output.stdout.is_empty() {
        // No leaks and no report emitted is a valid, boring outcome.
        return Ok(Vec::new());
    }

    let raw: Vec<GitleaksFinding> = serde_json::from_slice(&output.stdout)?;
    Ok(raw
        .into_iter()
        .map(|f| SecretFinding {
            rule_id: f.rule_id,
            file: f.file,
            start_line: f.start_line,
            commit: f.commit,
            description: f.description,
        })
        .collect())
}
