use crate::util::{Error, Result, digest_bytes};
use serde_json::{Value, json};
use std::{io::Read, path::Path};
pub struct Identity {
    pub harness: String,
    pub identity_kind: String,
    pub principal: String,
    pub organization: Option<String>,
    pub workspace: Option<String>,
}

impl Identity {
    fn fingerprint(&self) -> Result<String> {
        let bytes = serde_json::to_vec(&json!({
            "harness": self.harness,
            "identity_kind": self.identity_kind,
            "principal": self.principal,
            "organization": self.organization,
            "workspace": self.workspace,
        }))?;
        Ok(digest_bytes(&bytes))
    }
}

fn parse_antigravity_identity(output: &[u8]) -> Result<Identity> {
    if antigravity_needs_folder_trust(output) {
        return Err(antigravity_folder_trust_error());
    }
    let principal = extract_email(output).ok_or_else(|| {
        Error::new("Antigravity startup did not expose a signed-in account email")
    })?;
    let visible = String::from_utf8_lossy(output);
    let identity_kind = if visible.contains("Agent Platform") {
        "agent-platform"
    } else if visible.contains("Gemini API key") {
        return Err(Error::new(
            "Antigravity is using API-key authentication and exposes no user principal",
        ));
    } else {
        "antigravity-account"
    };
    Ok(Identity {
        harness: "antigravity".into(),
        identity_kind: identity_kind.into(),
        principal,
        organization: None,
        workspace: extract_labeled_value(&visible, "GCP Project:"),
    })
}

fn antigravity_needs_folder_trust(output: &[u8]) -> bool {
    let visible = String::from_utf8_lossy(output);
    visible.contains("Do you trust the contents of this project?")
        || visible.contains("Do you trust this folder?")
}

// Open agy in the checkout interactively and review its prompt; ahu never
// approves native folder trust automatically.
fn antigravity_folder_trust_error() -> Error {
    Error::diagnosed(crate::Diagnostic::NeedsNativeTrust)
}

fn antigravity_startup(
    executable: &Path,
    cwd: &Path,
    home: &Path,
    environment: &crate::Environment,
) -> Result<Vec<u8>> {
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    let mut master_fd = -1;
    let mut slave_fd = -1;
    let mut size = libc::winsize {
        ws_row: 30,
        ws_col: 120,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: openpty initializes two owned descriptors, which are wrapped
    // immediately below. No name or termios override is requested.
    if unsafe {
        libc::openpty(
            &mut master_fd,
            &mut slave_fd,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            // libc exposes a mutable winsize pointer on macOS and a const
            // pointer on Linux; a raw pointer coerces correctly on both.
            &raw mut size,
        )
    } != 0
    {
        return Err(Error::new(
            "cannot create bounded Antigravity status terminal",
        ));
    }
    // SAFETY: each descriptor was freshly returned by openpty and has one owner.
    let mut master = unsafe { std::fs::File::from_raw_fd(master_fd) };
    // SAFETY: each descriptor was freshly returned by openpty and has one owner.
    let slave = unsafe { std::fs::File::from_raw_fd(slave_fd) };
    let stdin = slave.try_clone()?;
    let stdout = slave.try_clone()?;
    let mut command = Command::new(executable);
    crate::process::configure(&mut command, home, environment);
    command
        .current_dir(cwd)
        .stdin(Stdio::from(stdin))
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(slave));
    command
        .env("TERM", "xterm-256color")
        .env("NO_COLOR", "1")
        .process_group(0);
    let mut child = command
        .spawn()
        .map_err(|_| Error::new("cannot start Antigravity identity probe"))?;
    // SAFETY: master owns a live PTY descriptor; only descriptor flags are changed.
    let flags = unsafe { libc::fcntl(master.as_raw_fd(), libc::F_GETFL) };
    if flags < 0
        || unsafe { libc::fcntl(master.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
    {
        crate::process::signal_group(child.id(), libc::SIGKILL);
        let _ = child.wait();
        return Err(Error::new("cannot bound Antigravity startup reads"));
    }
    let deadline = Instant::now() + Duration::from_secs(12);
    // The startup TUI can split the email, auth mode, and GCP project across
    // PTY writes. A recognized mode does not mean the fingerprint is complete:
    // wait for a bounded quiet window, including after "Agent Platform". The
    // CLI exposes no explicit identity-complete event, so this reduces late
    // field races without claiming that silence proves completeness. This does
    // not extend the overall probe deadline.
    let identity_settle = Duration::from_millis(2_500);
    let mut output = Vec::new();
    let mut last_output_at: Option<Instant> = None;
    let mut buffer = [0u8; 4096];
    let outcome = loop {
        if antigravity_needs_folder_trust(&output) {
            break Err(antigravity_folder_trust_error());
        }
        if extract_email(&output).is_some()
            && last_output_at.is_some_and(|last| last.elapsed() >= identity_settle)
        {
            break Ok(output);
        }
        if output.len() >= 64 * 1024 {
            break Err(Error::new(
                "Antigravity startup exceeded the identity output limit",
            ));
        }
        if Instant::now() >= deadline {
            break Err(Error::new("Antigravity startup identity check timed out"));
        }
        let mut descriptor = libc::pollfd {
            fd: master.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: descriptor is one initialized pollfd and master retains the fd.
        let ready = unsafe { libc::poll(&mut descriptor, 1, 150) };
        if ready < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            break Err(Error::new("cannot wait for Antigravity startup identity"));
        }
        if ready > 0 {
            match master.read(&mut buffer) {
                Ok(0) => {
                    // The CLI can print its prompt and exit before this loop
                    // reads again, so end-of-input is not itself a diagnosis.
                    // Report the folder-trust prompt if it already arrived:
                    // the generic terminal-closed error tells an operator
                    // nothing they can act on.
                    if antigravity_needs_folder_trust(&output) {
                        break Err(antigravity_folder_trust_error());
                    }
                    break Err(Error::new("Antigravity closed its startup terminal"));
                }
                Ok(count) => {
                    output.extend_from_slice(&buffer[..count]);
                    last_output_at = Some(Instant::now());
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => (),
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => (),
                Err(_) => break Err(Error::new("cannot read Antigravity startup identity")),
            }
        }
        match child.try_wait() {
            Ok(Some(status)) if !status.success() => {
                break Err(Error::new(
                    "Antigravity exited before exposing its account identity",
                ));
            }
            Err(_) => break Err(Error::new("cannot inspect Antigravity probe process")),
            _ => (),
        }
    };
    crate::process::signal_group(child.id(), libc::SIGKILL);
    let _ = child.wait();
    outcome
}

fn extract_email(bytes: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(bytes);
    for token in
        text.split(|c: char| c.is_whitespace() || matches!(c, '(' | ')' | '<' | '>' | '"' | '\''))
    {
        let token = token.trim_matches(|c: char| matches!(c, ',' | ';' | ':' | ']' | '['));
        let Some((local, domain)) = token.split_once('@') else {
            continue;
        };
        if local.is_empty()
            || domain.is_empty()
            || !domain.contains('.')
            || !token
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'+' | b'-' | b'@'))
        {
            continue;
        }
        return Some(token.to_owned());
    }
    None
}

fn extract_labeled_value(text: &str, label: &str) -> Option<String> {
    text.split_once(label)?
        .1
        .lines()
        .next()?
        .split_whitespace()
        .next()
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

pub(crate) fn call(
    harness: &str,
    p: &crate::ProbeParams,
    budget: bool,
    _model: Option<&str>,
    _ollama_host: Option<&str>,
    requested_identity: Option<&str>,
) -> Result<Value> {
    if requested_identity
        .is_some_and(|id| id != harness && !(harness == "opencode" && id == "ollama"))
    {
        return Err(Error::invalid());
    }
    if budget {
        {
            return Ok(json!({"status":"unsupported","windows":[],"signal_type":"unknown"}));
        }
    }

    let identity = match harness {
        "antigravity" => parse_antigravity_identity(&antigravity_startup(
            &p.native_executable,
            &p.project,
            &p.home,
            &p.environment,
        )?)?,

        _ => return Err(Error::invalid()),
    };
    Ok(
        json!({"status":"available","binding_harness":identity.harness,"fingerprint":identity.fingerprint()?,"effective_provider_address_verified":harness!="opencode","identity_kind":identity.identity_kind}),
    )
}
