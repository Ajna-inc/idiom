use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// Device platform — controls which platform-specific block the FCM v1
/// payload includes (`apns:` for iOS, `android:` for Android). Both
/// platforms share one mediator-side flow because iOS apps use Firebase's
/// APNS bridge (they hand out FCM tokens, not raw APNS tokens).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DevicePlatform {
    Ios,
    Android,
}

impl fmt::Display for DevicePlatform {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DevicePlatform::Ios => write!(f, "ios"),
            DevicePlatform::Android => write!(f, "android"),
        }
    }
}

impl FromStr for DevicePlatform {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "ios" | "apple" | "iphone" | "ipad" => Ok(DevicePlatform::Ios),
            "android" | "fcm" | "google" => Ok(DevicePlatform::Android),
            other => Err(format!("unknown device platform: {}", other)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_lowercase() {
        assert_eq!(DevicePlatform::Ios.to_string(), "ios");
        assert_eq!(DevicePlatform::Android.to_string(), "android");
    }

    #[test]
    fn parses_aliases() {
        assert_eq!(
            "iOS".parse::<DevicePlatform>().unwrap(),
            DevicePlatform::Ios
        );
        assert_eq!(
            "ANDROID".parse::<DevicePlatform>().unwrap(),
            DevicePlatform::Android
        );
        assert_eq!(
            "iphone".parse::<DevicePlatform>().unwrap(),
            DevicePlatform::Ios
        );
        assert!("symbian".parse::<DevicePlatform>().is_err());
    }

    #[test]
    fn serde_lowercase() {
        let s = serde_json::to_string(&DevicePlatform::Ios).unwrap();
        assert_eq!(s, "\"ios\"");
        let back: DevicePlatform = serde_json::from_str(&s).unwrap();
        assert_eq!(back, DevicePlatform::Ios);
    }
}
