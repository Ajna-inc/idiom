//! DateOnly type for ISO 18013-5 dates (without time components)

use chrono::{DateTime, Datelike, NaiveDate, Utc};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// DateOnly represents a calendar date without time or timezone
///
/// Serializes to CBOR as a tdate (tag 1004) with full-date format "YYYY-MM-DD"
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DateOnly {
    inner: NaiveDate,
}

impl DateOnly {
    /// Create a new DateOnly from year, month, day
    ///
    /// # Panics
    /// Panics if the date is invalid (e.g., February 30)
    pub fn new(year: i32, month: u32, day: u32) -> Self {
        Self {
            inner: NaiveDate::from_ymd_opt(year, month, day).expect("Invalid date"),
        }
    }

    /// Try to create a new DateOnly from year, month, day
    ///
    /// Returns None if the date is invalid
    pub fn try_new(year: i32, month: u32, day: u32) -> Option<Self> {
        NaiveDate::from_ymd_opt(year, month, day).map(|inner| Self { inner })
    }

    /// Get the current date (UTC)
    pub fn today() -> Self {
        Self {
            inner: Utc::now().date_naive(),
        }
    }

    /// Create from a DateTime<Utc>
    pub fn from_datetime(dt: DateTime<Utc>) -> Self {
        Self {
            inner: dt.date_naive(),
        }
    }

    /// Create from NaiveDate
    pub fn from_naive_date(date: NaiveDate) -> Self {
        Self { inner: date }
    }

    /// Get year
    pub fn year(&self) -> i32 {
        self.inner.year()
    }

    /// Get month (1-12)
    pub fn month(&self) -> u32 {
        self.inner.month()
    }

    /// Get day (1-31)
    pub fn day(&self) -> u32 {
        self.inner.day()
    }

    /// Parse from ISO 8601 date string "YYYY-MM-DD"
    pub fn parse(s: &str) -> Result<Self, chrono::ParseError> {
        NaiveDate::parse_from_str(s, "%Y-%m-%d").map(|inner| Self { inner })
    }

    /// Get the underlying NaiveDate
    pub fn as_naive_date(&self) -> &NaiveDate {
        &self.inner
    }

    /// Convert to DateTime<Utc> at midnight
    pub fn to_datetime_utc(&self) -> DateTime<Utc> {
        DateTime::from_naive_utc_and_offset(self.inner.and_hms_opt(0, 0, 0).unwrap(), Utc)
    }
}

impl std::fmt::Display for DateOnly {
    /// Formats as ISO 8601 date string "YYYY-MM-DD".
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.inner.format("%Y-%m-%d"))
    }
}

impl From<NaiveDate> for DateOnly {
    fn from(date: NaiveDate) -> Self {
        Self::from_naive_date(date)
    }
}

impl From<DateOnly> for NaiveDate {
    fn from(date: DateOnly) -> Self {
        date.inner
    }
}

// Custom serialization to ISO 8601 string
impl Serialize for DateOnly {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

// Custom deserialization from ISO 8601 string
impl<'de> Deserialize<'de> for DateOnly {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        DateOnly::parse(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_date_only_creation() {
        let date = DateOnly::new(2024, 10, 24);
        assert_eq!(date.year(), 2024);
        assert_eq!(date.month(), 10);
        assert_eq!(date.day(), 24);
    }

    #[test]
    fn test_date_only_formatting() {
        let date = DateOnly::new(2024, 1, 5);
        assert_eq!(date.to_string(), "2024-01-05");
    }

    #[test]
    fn test_date_only_parsing() {
        let date = DateOnly::parse("2024-10-24").unwrap();
        assert_eq!(date.year(), 2024);
        assert_eq!(date.month(), 10);
        assert_eq!(date.day(), 24);
    }

    #[test]
    fn test_date_only_serialization() {
        let date = DateOnly::new(2024, 10, 24);
        let json = serde_json::to_string(&date).unwrap();
        assert_eq!(json, "\"2024-10-24\"");

        let deserialized: DateOnly = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, date);
    }

    #[test]
    fn test_date_only_comparison() {
        let date1 = DateOnly::new(2024, 10, 24);
        let date2 = DateOnly::new(2024, 10, 25);
        assert!(date1 < date2);
    }

    #[test]
    fn test_try_new_invalid() {
        let invalid = DateOnly::try_new(2024, 2, 30);
        assert!(invalid.is_none());
    }

    #[test]
    #[should_panic]
    fn test_new_invalid_panics() {
        DateOnly::new(2024, 2, 30);
    }
}
