use dashmap::DashMap;
use mimalloc::MiMalloc;
use std::time::{Duration, Instant};

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

pub struct AnalysisCache {
    cache: DashMap<String, (Vec<MaliciousBehavior>, Instant)>,
    max_size: usize,
    ttl: Duration,
}

impl AnalysisCache {
    pub fn new(max_size: usize, ttl_seconds: u64) -> Self {
        Self {
            cache: DashMap::new(),
            max_size,
            ttl: Duration::from_secs(ttl_seconds),
        }
    }

    pub fn get(&self, key: &str) -> Option<Vec<MaliciousBehavior>> {
        self.cache.get(key).and_then(|entry| {
            let (behaviors, timestamp) = entry.value();
            if timestamp.elapsed() < self.ttl {
                Some(behaviors.clone())
            } else {
                self.cache.remove(key);
                None
            }
        })
    }

    pub fn insert(&self, key: String, value: Vec<MaliciousBehavior>) {
        if self.cache.len() >= self.max_size {
            self.cleanup();
        }
        self.cache.insert(key, (value, Instant::now()));
    }

    fn cleanup(&self) {
        let now = Instant::now();
        self.cache.retain(|_, (_, timestamp)| {
            timestamp.elapsed() < self.ttl
        });
    }
} 