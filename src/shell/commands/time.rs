//! # Shell Command: Real-Time Clock & Uptime Display (`time`, `date`)
//!
//! Provides the `time` shell command querying the CMOS RTC and system uptime tick counter.

use uefi::proto::console::text::Color;
use crate::console::set_color;
use crate::shell::command::Command;
use crate::shell::state::ShellState;

/// Shell command querying the CMOS RTC time and system uptime.
pub struct TimeCommand;

impl Command for TimeCommand {
    fn name(&self) -> &'static str {
        "time"
    }

    fn aliases(&self) -> &'static [&'static str] {
        &["date"]
    }

    fn description(&self) -> &'static str {
        "Query hardware Real-Time Clock (RTC) via UEFI runtime services"
    }

    fn usage(&self) -> &'static str {
        "time"
    }

    fn execute(&self, _args: &[&str], _state: &mut ShellState) {
        match uefi::runtime::get_time() {
            Ok(t) => {
                set_color(Color::LightGreen, Color::Black);
                println!("UEFI Hardware RTC: {:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
                    t.year(), t.month(), t.day(), t.hour(), t.minute(), t.second());
            }
            Err(err) => {
                set_color(Color::LightRed, Color::Black);
                println!("[!] Could not read UEFI RTC time: {:?}", err);
            }
        }
    }
}
