use ahu_harness_native::call;
use serde_json::{Value, json};
use std::os::unix::fs::PermissionsExt;
use std::{fs, path::PathBuf};

struct Fixture {
    _tmp: tempfile::TempDir,
    root: PathBuf,
    home: PathBuf,
    exe: PathBuf,
}
impl Fixture {
    fn new(body: &str) -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().canonicalize().unwrap();
        let home = root.join("home");
        fs::create_dir(&home).unwrap();
        let exe = root.join("native");
        fs::write(&exe, format!("#!/bin/sh\n{body}\n")).unwrap();
        fs::set_permissions(&exe, fs::Permissions::from_mode(0o700)).unwrap();
        Self {
            _tmp: tmp,
            root,
            home,
            exe,
        }
    }
    fn probe(&self) -> Value {
        json!({"project":self.root,"home":self.home,"native_executable":self.exe,"environment":{}})
    }
    fn setup(&self) -> Value {
        json!({"project":self.root,"home":self.home,"ahu_executable":self.exe,"skills":[]})
    }
}

#[test]
fn setup_proposes_all_provider_formats_and_never_writes() {
    let f = Fixture::new("exit 99");
    for h in ["antigravity"] {
        let mut p = f.setup();
        p["skills"] = json!([{"name":"test-skill","text":"# synthetic\n"}]);
        let result = call(h, "setup", &p).unwrap();
        let changes = result["changes"].as_array().unwrap();
        assert!(changes.len() >= 2);
        for change in changes {
            assert!(change["expected_before_sha256"].is_null());
            assert!(!PathBuf::from(change["path"].as_str().unwrap()).exists());
        }
        let text = changes[0]["text"].as_str().unwrap();
        if h == "codex" {
            let v: toml::Value = toml::from_str(text).unwrap();
            assert_eq!(
                v["mcp_servers"]["ahu"]["tools"]["ahu_agents_list"]["approval_mode"].as_str(),
                Some("approve")
            );
        } else {
            let v: Value = serde_json::from_str(text).unwrap();
            let key = if h == "opencode" { "mcp" } else { "mcpServers" };
            assert!(v[key]["ahu"].is_object());
            if h == "kiro" {
                assert_eq!(v[key]["ahu"]["env"]["AHU_TASK_ID"], "${AHU_TASK_ID}");
            }
        }
    }
}

#[test]
fn antigravity_account_banner_is_observed_without_input_or_approval() {
    let f = Fixture::new(
        "printf 'fixture@example.invalid Agent Platform GCP Project: synthetic-workspace\\n'; sleep 5",
    );
    let result = call("antigravity", "auth", &f.probe()).unwrap();
    assert_eq!(result["status"], "available");
    assert!(!result.to_string().contains("fixture@example"));
    fs::write(
        &f.exe,
        "#!/bin/sh\nprintf 'Do you trust this folder?\\n'; sleep 5\n",
    )
    .unwrap();
    let error = call("antigravity", "auth", &f.probe()).unwrap_err();
    assert_eq!(
        error.diagnostic,
        Some(ahu_harness_native::Diagnostic::NeedsNativeTrust)
    );
}

#[test]
fn masked_native_overrides_never_probe_the_default_account() {
    let f = Fixture::new("touch should-not-run; exit 99");
    for (harness, variable) in [
        ("codex", "CODEX_HOME"),
        ("claude-code", "ANTHROPIC_API_KEY"),
        ("opencode", "OLLAMA_HOST"),
        ("kiro", "KIRO_HOME"),
        ("antigravity", "GEMINI_API_KEY"),
    ] {
        let mut p = f.probe();
        p["environment_names"] = json!([variable]);
        assert!(call(harness, "auth", &p).is_err());
        assert!(call(harness, "budget", &p).is_err());
    }
    assert!(!f.root.join("should-not-run").exists());
}

#[test]
fn antigravity_auth_suppresses_color_and_returns_only_account_fingerprint() {
    let f = Fixture::new(
        "test \"$NO_COLOR\" = 1 || exit 2\nprintf 'Signed in as fixture@example.invalid\\n'",
    );
    for inherited in ["", "0", "1"] {
        let mut params = f.probe();
        params["environment"]["NO_COLOR"] = json!(inherited);
        let result = call("antigravity", "auth", &params).unwrap();
        assert_eq!(result["status"], "available");
        assert!(!result.to_string().contains("fixture@example.invalid"));
    }
}
