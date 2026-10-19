//! Production-expression integration tests, including nested mixing and adverse work patterns.
#[path = "support/audio_workload.rs"]
mod workload;
use effectcraft_expr::Expressions;
use effectcraft_keyframe::Value;
use effectcraft_project::{Layer, Property};
use effectcraft_render::{
    EvalCtx, ExprHost,
    audio::{AudioError, MixControl, mix_comp, mix_comp_with_control},
};
use effectcraft_time::Tick;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

/// Forces the full JavaScript path as an independent oracle for prepared expressions.
struct JavaScript;
impl ExprHost for JavaScript {
    fn eval(&self, ctx: &EvalCtx, layer: &Layer, prop: &Property, value: &Value) -> Result<Value, String> {
        Expressions.eval(ctx, layer, prop, value)
    }
}

/// Check numeric semantics and the boundary where expressions must fall back to JavaScript.
#[test]
fn scalar_preparation_matches_javascript_and_rejects_other_syntax() {
    let (p, cid) = workload::project(1, 0, None);
    let comp = p.comp(cid).unwrap();
    let layer = &comp.layers[0];
    let prop = layer.props.get("timeRemap").unwrap();
    let texts = [
        "0.25 + time * 0.5",
        "time * time * .01 + value",
        "(time + value) / 3 - -0.5",
        "1e-3 * time;",
        "value / (time-time)",
        "-0",
        "1e308 * 1e308 - 1e308",
        "time - value - 1",
        "time / 3 / 7",
        "+time",
    ];
    for text in texts {
        let prepared = Expressions.prepare_audio(text).unwrap();
        for time in [-123.0, -0.0, 0.0, 1.0 / 48000.0, 0.1, 1.0, 179.99] {
            let ctx = EvalCtx::new(&p, cid, comp, Tick::from_seconds_f64(time));
            for value in [-0.0, 0.25, 123.75] {
                let actual = prepared.evaluate(ctx.time.seconds(), value).map(f64::to_bits);
                let expected = effectcraft_expr::evaluate(&Expressions, &ctx, layer, prop, &Value::Scalar(value), text).ok().map(|v| v.as_f64().to_bits());
                assert_eq!(actual, expected, "{text}, time={time}, value={value}");
            }
        }
    }
    for text in [
        "Math.sin(time)",
        "time++",
        "--time",
        "0x10",
        "012",
        "time ** 2",
        "var x = time; x",
        "time ? 1 : 0",
        "value[0]",
        "time // comment",
        "time +",
        "/*comment*/time",
    ] {
        assert!(Expressions.prepare_audio(text).is_none(), "{text}");
    }
    assert!(Expressions.prepare_audio(&format!("{}time{}", "(".repeat(40), ")".repeat(40))).is_none());
    assert!(Expressions.prepare_audio(&"time+".repeat(300)).is_none());
}

/// Compare complete mixed buffers, including layered/nested projects and a non-dividing sample rate.
#[test]
fn medium_nested_project_matches_full_runtime_and_block_boundaries() {
    for (layers, depth, text) in
        [(12, 0, "0.25 + time * time * 0.01"), (4, 2, "0.25 + time * 0.5"), (2, 0, "0.25 + Math.sin(time) * Math.sin(time)"), (2, 0, "value / (time-time)")]
    {
        let (p, cid) = workload::project(layers, depth, Some(text));
        let source = workload::Source::default();
        let expected = mix_comp(&p, &source, Some(&JavaScript), cid, Tick::ZERO, 256, 44100).unwrap();
        let actual = mix_comp(&p, &source, Some(&Expressions), cid, Tick::ZERO, 256, 44100).unwrap();
        assert_eq!(actual, expected, "{layers} layers, depth {depth}, {text}");
        let mut split = mix_comp(&p, &source, Some(&Expressions), cid, Tick::ZERO, 73, 44100).unwrap();
        let mut start = Tick::from_units(73, 44100);
        if start.to_units_floor(44100) < 73 {
            start.0 += 1;
        }
        split.extend(mix_comp(&p, &source, Some(&Expressions), cid, start, 183, 44100).unwrap());
        assert_eq!(split, actual, "block boundary: {text}");
    }
}

/// Distinguish a reusable jump pattern from new-page traversal that must exhaust shared work.
#[test]
fn repeated_jumps_cache_pages_and_unbounded_traversal_returns_error() {
    let (p, cid) = workload::project(1, 0, Some("Math.floor(time * 48000) % 2 ? 10 : 0"));
    let source = workload::Source::default();
    let samples = mix_comp(&p, &source, Some(&Expressions), cid, Tick::ZERO, 1024, 48000).unwrap();
    assert_eq!(samples.len(), 2048);
    assert_eq!(mix_comp(&p, &source, Some(&Expressions), cid, Tick::ZERO, usize::MAX, 48000), Err(AudioError::WorkLimit));
    assert_eq!(source.reads.load(Ordering::Relaxed), 2);
    for depth in [0, 2] {
        let (p, cid) = workload::project(4, depth, Some("time * 100000"));
        let source = workload::Source::default();
        let control = MixControl { max_work: Some(100_000), ..Default::default() };
        assert_eq!(mix_comp_with_control(&p, &source, Some(&Expressions), cid, Tick::ZERO, 1024, 48000, &control), Err(AudioError::WorkLimit));
        assert!(source.frames.load(Ordering::Relaxed) <= 100_000);
    }
}

/// Interrupt an expensive script and reuse its thread-local runtime for a successful mix.
#[test]
fn cancellation_interrupts_running_javascript_and_does_not_poison_next_mix() {
    let (p, cid) = workload::project(1, 0, Some("var n = 0; for (var i = 0; i < 1000000; i++) { n += Math.sin(i); } n"));
    let cancel = Arc::new(AtomicBool::new(false));
    let signal = cancel.clone();
    let (done, completion) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        let source = workload::Source::default();
        let control = MixControl { cancel: Some(signal), ..Default::default() };
        let result = mix_comp_with_control(&p, &source, Some(&Expressions), cid, Tick::ZERO, 1024, 48000, &control);
        assert_eq!(result, Err(AudioError::Cancelled));
        assert_eq!(source.reads.load(Ordering::Relaxed), 0);
        let (p, cid) = workload::project(1, 0, Some("Math.sin(time)"));
        assert!(mix_comp(&p, &source, Some(&Expressions), cid, Tick::ZERO, 32, 48000).is_ok());
        done.send(()).unwrap();
    });
    std::thread::sleep(std::time::Duration::from_millis(50));
    cancel.store(true, Ordering::Relaxed);
    completion.recv_timeout(std::time::Duration::from_secs(3)).expect("cancellation must interrupt the script, not wait for every sample");
    worker.join().unwrap();
}
