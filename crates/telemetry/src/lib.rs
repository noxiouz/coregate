use std::collections::BTreeMap;
use std::time::Instant;

#[derive(Debug, Default)]
pub struct StageTimer {
    started: BTreeMap<String, Instant>,
    done_ms: BTreeMap<String, u64>,
}

impl StageTimer {
    pub fn start(&mut self, stage: &str) {
        self.started.insert(stage.to_string(), Instant::now());
    }

    pub fn end(&mut self, stage: &str) {
        if let Some(started) = self.started.remove(stage) {
            self.done_ms
                .insert(stage.to_string(), started.elapsed().as_millis() as u64);
        }
    }

    pub fn snapshot(&self) -> Vec<(String, u64)> {
        self.done_ms.iter().map(|(k, v)| (k.clone(), *v)).collect()
    }
}
