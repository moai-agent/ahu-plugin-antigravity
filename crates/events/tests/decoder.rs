use ahu_harness_events::Decoder;
use serde_json::{Value, json};

fn feed(decoder: &mut Decoder, event: Value) -> Value {
    decoder
        .observe_stdout(&serde_json::to_vec(&event).unwrap())
        .unwrap()
}

#[test]
fn selected_provider_keeps_terminal_summary_and_unknown_usage_separate() {
    let fixtures = [
        (
            "codex",
            vec![
                json!({"type":"item.completed","item":{"type":"agent_message","text":"answer"}}),
                json!({"type":"turn.completed"}),
            ],
        ),
        (
            "claude-code",
            vec![json!({"type":"result","subtype":"success","is_error":false,"result":"answer"})],
        ),
        (
            "antigravity",
            vec![json!({"type":"result","result":{"status":"success","response":"answer"}})],
        ),
        (
            "opencode",
            vec![
                json!({"type":"text","part":{"text":"answer"}}),
                json!({"type":"step_finish","part":{"id":"end","reason":"stop"}}),
            ],
        ),
        (
            "kiro",
            vec![
                json!({"type":"runStarted","data":{"engine":"v3","payloadSchema":"acp","acpProtocolVersion":1}}),
                json!({"type":"runFinished","data":{"sessionId":"sess_synthetic","status":"success","stopReason":"end_turn","finalText":"answer","finalTextTruncated":false}}),
            ],
        ),
    ];
    for (harness, events) in fixtures
        .into_iter()
        .filter(|(harness, _)| *harness == "antigravity")
    {
        let mut decoder = Decoder::new(harness).unwrap();
        for event in events {
            feed(&mut decoder, event);
        }
        let result = decoder.finish().unwrap();
        assert_eq!(result["terminal"], true, "{harness}");
        assert_eq!(result["failed"], false, "{harness}: {result}");
        assert_eq!(result["summary"], "answer");
        assert!(result["usage"]["total"].is_null());
        assert!(result["cost"].get("usd").is_none());
        assert_eq!(decoder.finish().unwrap(), result);
    }
    assert!(Decoder::new("invented").is_err());
}
