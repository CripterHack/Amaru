use criterion::{black_box, criterion_group, criterion_main, Criterion};
use std::time::Duration;

fn benchmark_analysis(c: &mut Criterion) {
    let analyzer = BehaviorAnalyzer::new().unwrap();
    let test_files = generate_test_files(100).unwrap();

    let mut group = c.benchmark_group("behavior_analysis");
    group.measurement_time(Duration::from_secs(10));
    group.sample_size(10);

    group.bench_function("parallel_analysis", |b| {
        b.iter(|| {
            for file in &test_files {
                let hash = calculate_file_hash(black_box(file)).unwrap();
                analyzer.analyze_optimized(&std::fs::read(file).unwrap(), &hash).unwrap();
            }
        })
    });

    group.finish();
}

criterion_group!(benches, benchmark_analysis);
criterion_main!(benches); 