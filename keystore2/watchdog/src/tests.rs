// Copyright 2021, The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Watchdog tests.

use super::*;
use std::sync::atomic;
use std::thread;
use std::time::Duration;

/// Count the number of times `Debug::fmt` is invoked.
#[derive(Default, Clone)]
struct DebugCounter(Arc<atomic::AtomicU8>);
impl DebugCounter {
    fn value(&self) -> u8 {
        self.0.load(atomic::Ordering::Relaxed)
    }
}
impl std::fmt::Debug for DebugCounter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        let count = self.0.fetch_add(1, atomic::Ordering::Relaxed);
        write!(f, "hit_count: {count}")
    }
}

#[test]
fn test_watchdog() {
    android_logger::init_once(
        android_logger::Config::default()
            .with_tag("keystore2_watchdog_tests")
            .with_max_level(log::LevelFilter::Debug),
    );

    let wd = Watchdog::new(Duration::from_secs(3));
    let hit_counter = DebugCounter::default();
    let wp =
        Watchdog::watch_with(&wd, "test_watchdog", Duration::from_millis(100), hit_counter.clone());
    assert_eq!(0, hit_counter.value());
    thread::sleep(Duration::from_millis(500));
    assert_eq!(1, hit_counter.value());
    thread::sleep(Duration::from_secs(1));
    assert_eq!(1, hit_counter.value());

    drop(wp);
    thread::sleep(Duration::from_secs(10));
    assert_eq!(1, hit_counter.value());
    let (_, ref state) = *wd.state;
    let state = state.lock().unwrap();
    assert_eq!(state.state, State::NotRunning);
}

#[test]
fn test_watchdog_backoff() {
    android_logger::init_once(
        android_logger::Config::default()
            .with_tag("keystore2_watchdog_tests")
            .with_max_level(log::LevelFilter::Debug),
    );

    let wd = Watchdog::new(Duration::from_secs(3));
    let hit_counter = DebugCounter::default();
    let wp =
        Watchdog::watch_with(&wd, "test_watchdog", Duration::from_millis(100), hit_counter.clone());
    assert_eq!(0, hit_counter.value());
    thread::sleep(Duration::from_millis(500));
    assert_eq!(1, hit_counter.value());
    thread::sleep(Duration::from_secs(6));
    assert_eq!(2, hit_counter.value());
    thread::sleep(Duration::from_secs(11));
    assert_eq!(3, hit_counter.value());

    drop(wp);
    thread::sleep(Duration::from_secs(4));
    assert_eq!(3, hit_counter.value());
}
