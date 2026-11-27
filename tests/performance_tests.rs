mod support;

use amaru::BehaviorAnalyzer;
use std::{
    hint::black_box,
    time::{Duration, Instant},
};

#[test]
fn benchmark_parallel_behavior_analysis() {
    let analyzer = BehaviorAnalyzer::new();
    let samples: Vec<_> = (0..100u8)
        .map(|index| support::import_fixture(support::INJECTION, &[index]))
        .collect();
    let start = Instant::now();
    for _ in 0..10 {
        for sample in &samples {
            assert!(!analyzer
                .analyze_optimized(black_box(sample), "")
                .unwrap()
                .is_empty());
        }
    }
    assert!(start.elapsed() < Duration::from_secs(10));
}
