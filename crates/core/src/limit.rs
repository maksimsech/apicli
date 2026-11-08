use std::fmt;

use serde::{Deserialize, Serialize};

const DAY_MS: u64 = 86_400_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unit {
    Second,
    Minute,
    Hour,
    Day,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Rate {
    pub count: u32,
    pub unit: Unit,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct Limits {
    pub rate: Option<Rate>,
    pub burst: Option<u32>,
    pub daily: Option<u32>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Bucket {
    #[serde(default)]
    tat: u64,
    #[serde(default)]
    day: u64,
    #[serde(default)]
    today: u32,
    #[serde(default)]
    blocked_until: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Wait {
    Rate(u64),
    Daily(u64),
    Upstream(u64),
}

impl Unit {
    fn millis(self) -> u64 {
        match self {
            Unit::Second => 1_000,
            Unit::Minute => 60_000,
            Unit::Hour => 3_600_000,
            Unit::Day => DAY_MS,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Unit::Second => "s",
            Unit::Minute => "min",
            Unit::Hour => "h",
            Unit::Day => "day",
        }
    }
}

impl Rate {
    pub fn parse(text: &str) -> Result<Rate, String> {
        let invalid =
            || format!("{text} is not a rate, use a count per s, min, h or day, like 60/min");
        let (count, unit) = text.split_once('/').ok_or_else(invalid)?;
        let count = count
            .trim()
            .parse::<u32>()
            .ok()
            .filter(|count| *count > 0)
            .ok_or_else(invalid)?;
        let unit = match unit.trim() {
            "s" | "sec" | "second" => Unit::Second,
            "m" | "min" | "minute" => Unit::Minute,
            "h" | "hour" => Unit::Hour,
            "d" | "day" => Unit::Day,
            _ => return Err(invalid()),
        };
        Ok(Rate { count, unit })
    }

    fn interval(self) -> u64 {
        (self.unit.millis() / u64::from(self.count)).max(1)
    }
}

impl fmt::Display for Rate {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "{}/{}", self.count, self.unit.name())
    }
}

impl TryFrom<String> for Rate {
    type Error = String;

    fn try_from(text: String) -> Result<Self, String> {
        Rate::parse(&text)
    }
}

impl From<Rate> for String {
    fn from(rate: Rate) -> String {
        rate.to_string()
    }
}

impl Limits {
    fn tolerance(&self, rate: Rate) -> u64 {
        rate.interval() * u64::from(self.burst.unwrap_or(rate.count).max(1) - 1)
    }
}

impl fmt::Display for Limits {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        let mut parts = Vec::new();
        if let Some(rate) = self.rate {
            parts.push(rate.to_string());
            parts.push(format!("burst {}", self.burst.unwrap_or(rate.count)));
        }
        if let Some(daily) = self.daily {
            parts.push(format!("{daily}/day"));
        }
        if parts.is_empty() {
            write!(formatter, "no limit")
        } else {
            write!(formatter, "{}", parts.join(", "))
        }
    }
}

impl Bucket {
    pub fn take(&mut self, limits: &Limits, now: u64) -> Result<(), Wait> {
        if self.blocked_until > now {
            return Err(Wait::Upstream(self.blocked_until - now));
        }
        let day = now / DAY_MS;
        let today = if self.day == day { self.today } else { 0 };
        if let Some(daily) = limits.daily
            && today >= daily
        {
            return Err(Wait::Daily((day + 1) * DAY_MS - now));
        }
        let mut tat = self.tat;
        if let Some(rate) = limits.rate {
            let start = self.tat.max(now);
            let tolerance = limits.tolerance(rate);
            if start - now > tolerance {
                return Err(Wait::Rate(start - now - tolerance));
            }
            tat = start + rate.interval();
        }
        self.tat = tat;
        self.day = day;
        self.today = today + 1;
        Ok(())
    }

    pub fn block(&mut self, until: u64) {
        self.blocked_until = self.blocked_until.max(until);
    }

    pub fn remaining(&self, limits: &Limits, now: u64) -> Option<u32> {
        let mut remaining = limits.rate.map(|rate| {
            let backlog = self.tat.max(now) - now;
            let tolerance = limits.tolerance(rate);
            if backlog > tolerance {
                0
            } else {
                u32::try_from((tolerance - backlog) / rate.interval() + 1).unwrap_or(u32::MAX)
            }
        });
        if let Some(daily) = limits.daily {
            let today = if self.day == now / DAY_MS {
                self.today
            } else {
                0
            };
            let left = daily.saturating_sub(today);
            remaining = Some(remaining.map_or(left, |remaining| remaining.min(left)));
        }
        if self.blocked_until > now {
            remaining = Some(0);
        }
        remaining
    }
}

impl Wait {
    pub fn millis(self) -> u64 {
        match self {
            Wait::Rate(ms) | Wait::Daily(ms) | Wait::Upstream(ms) => ms,
        }
    }
}
