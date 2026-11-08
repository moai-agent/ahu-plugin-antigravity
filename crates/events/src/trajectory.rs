//! Bounded projections of native event streams. No payloads or identifiers are
//! serialized; a repeated tool is not necessarily redundant or unproductive.

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Coverage {
    #[default]
    None,
    Partial,
    /// Complete only for the supported shapes in the captured native stream,
    /// never a claim about provider internals or helper work.
    CompleteObservedStream,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    #[default]
    Unsupported,
    CodexTurns,
    ClaudeAssistantMessages,
    OpencodeSteps,
    KiroSessionUpdates,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    pub source: Source,
    pub coverage: Coverage,
    /// Independent partial metering, never model steps, tokens or USD.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metering: Option<Metering>,
    pub steps: Option<u64>,
    pub tool_calls: Option<u64>,
    /// Calls with an observed, classified terminal outcome. Absent in legacy records.
    #[serde(default)]
    pub completed_tool_calls: Option<u64>,
    pub tool_errors: Option<u64>,
    pub repeated_tool_calls: Option<u64>,
    pub repeated_tool_errors: Option<u64>,
    /// Success after an observed error from the same tool; not task recovery.
    pub tool_recoveries: Option<u64>,
    pub malformed_events: u64,
    pub unclassified_events: u64,
    pub tracking_limited: bool,
    pub stream_incomplete: bool,
}

/// Kiro V3 session-info evidence. Amounts are sums of accepted observations,
/// not complete attempt/session accounting. Context is a window snapshot.
/// No native identifiers, tool names, breakdown contents or payloads persist.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Metering {
    pub context_usage_percent: Option<f64>,
    pub peak_context_usage_percent: Option<f64>,
    /// Prompt completions may contain multiple model requests. Not `steps`.
    pub prompt_completions: Option<u64>,
    pub observed_credits: Option<f64>,
    pub credit_observations: u64,
    pub observed_elapsed_ms: Option<f64>,
    pub elapsed_observations: u64,
    pub duplicate_completions: u64,
    pub rejected_updates: u64,
    /// Includes replay before a live prompt marker and unanchored completions.
    pub unattributed_completions: u64,
}

impl Metering {}

impl Observation {
    pub fn complete(&self) -> bool {
        self.coverage == Coverage::CompleteObservedStream
            && self.source != Source::Unsupported
            && !self.tracking_limited
            && !self.stream_incomplete
            && self.malformed_events == 0
            && self.unclassified_events == 0
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Observer {
    #[serde(flatten)]
    pub observation: Observation,

    #[serde(skip)]
    started: bool,
    #[serde(skip)]
    ended: bool,
    #[serde(skip)]
    pending: usize,
}

fn string<'a>(v: &'a Value, path: &str) -> Option<&'a str> {
    v.pointer(path).and_then(Value::as_str)
}

impl Observer {
    pub fn incomplete(&mut self) {
        self.observation.stream_incomplete = true;
        self.refresh();
    }
    pub fn malformed(&mut self) {
        self.observation.malformed_events = self.observation.malformed_events.saturating_add(1);
        self.incomplete();
    }
    fn unknown(&mut self) {
        self.observation.unclassified_events =
            self.observation.unclassified_events.saturating_add(1);
    }
    fn refresh(&mut self) {
        let o = &mut self.observation;
        o.coverage = if o.source == Source::Unsupported {
            Coverage::None
        } else if o.source == Source::KiroSessionUpdates {
            // ACP call outcomes are observable, but model turns and native
            // helper attribution are not. Never certify whole-stream coverage.
            Coverage::Partial
        } else if self.started
            && self.ended
            && !o.stream_incomplete
            && !o.tracking_limited
            && o.malformed_events == 0
            && o.unclassified_events == 0
            && self.pending == 0
        {
            Coverage::CompleteObservedStream
        } else {
            Coverage::Partial
        };
    }

    pub fn observe(&mut self, _harness: &str, v: &Value) {
        let source = Source::Unsupported;
        if source == Source::Unsupported {
            return;
        }

        if self.observation.source == Source::Unsupported {
            self.observation.source = source;
            self.observation.steps = Some(0);
            self.observation.tool_calls = Some(0);
            self.observation.completed_tool_calls = Some(0);
            self.observation.tool_errors = Some(0);
            self.observation.repeated_tool_calls = Some(0);
            self.observation.repeated_tool_errors = Some(0);
            self.observation.tool_recoveries = Some(0);
        } else if self.observation.source != source {
            self.incomplete();
            return;
        }
        // Native helper messages are outside the owning agent's trajectory.

        let _kind = string(v, "/type")
            .or_else(|| string(v, "/event"))
            .unwrap_or("");
        self.unknown();
        self.refresh();
    }
}
