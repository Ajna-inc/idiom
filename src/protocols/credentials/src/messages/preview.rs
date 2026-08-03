use serde::{Deserialize, Serialize};

/// A single attribute in a `propose-credential` or `offer-credential`
/// preview. `name` is unique within a preview, `value` is the raw
/// user-facing string, and `mime_type` (when present) lets renderers
/// pick the right view (e.g. `image/jpeg` for inline avatars).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CredentialPreviewAttribute {
    pub name: String,
    pub value: String,
    #[serde(rename = "mime-type", skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
}

impl CredentialPreviewAttribute {
    pub fn new(
        name: impl Into<String>,
        value: impl Into<String>,
        mime_type: Option<String>,
    ) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
            mime_type,
        }
    }
}

/// Compare two preview attribute lists for equality, treating order as
/// insignificant but rejecting duplicate names within a single list.
pub fn are_preview_attributes_equal(
    a: &[CredentialPreviewAttribute],
    b: &[CredentialPreviewAttribute],
) -> bool {
    if a.len() != b.len() {
        return false;
    }

    // Reject lists with duplicate names — semantically meaningless and a
    // common source of issuer/holder mismatch.
    let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for attr in a {
        if !seen.insert(attr.name.as_str()) {
            return false;
        }
    }
    seen.clear();
    for attr in b {
        if !seen.insert(attr.name.as_str()) {
            return false;
        }
    }

    // Pairwise compare by name (order-insensitive).
    let mut b_by_name: std::collections::HashMap<&str, &CredentialPreviewAttribute> =
        std::collections::HashMap::with_capacity(b.len());
    for attr in b {
        b_by_name.insert(attr.name.as_str(), attr);
    }

    for attr in a {
        match b_by_name.get(attr.name.as_str()) {
            Some(other) => {
                if attr != *other {
                    return false;
                }
            }
            None => return false,
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attr(name: &str, value: &str, mime: Option<&str>) -> CredentialPreviewAttribute {
        CredentialPreviewAttribute::new(name, value, mime.map(|s| s.to_string()))
    }

    #[test]
    fn returns_true_if_attributes_equal() {
        let first = vec![
            attr("firstName", "firstValue", Some("text/grass")),
            attr("secondName", "secondValue", Some("text/grass")),
        ];
        let second = vec![
            attr("firstName", "firstValue", Some("text/grass")),
            attr("secondName", "secondValue", Some("text/grass")),
        ];
        assert!(are_preview_attributes_equal(&first, &second));
    }

    #[test]
    fn returns_false_for_different_mime_type() {
        let first = vec![attr("secondName", "secondValue", Some("text/grass"))];
        let second = vec![attr("secondName", "secondValue", Some("text/notGrass"))];
        assert!(!are_preview_attributes_equal(&first, &second));
    }

    #[test]
    fn returns_false_for_different_value() {
        let first = vec![attr("secondName", "secondValue", Some("text/grass"))];
        let second = vec![attr("secondName", "thirdValue", Some("text/grass"))];
        assert!(!are_preview_attributes_equal(&first, &second));
    }

    #[test]
    fn returns_false_for_different_name() {
        let first = vec![attr("secondName", "secondValue", Some("text/grass"))];
        let second = vec![attr("thirdName", "secondValue", Some("text/grass"))];
        assert!(!are_preview_attributes_equal(&first, &second));
    }

    #[test]
    fn returns_false_for_different_lengths() {
        let first = vec![attr("secondName", "secondValue", Some("text/grass"))];
        let second = vec![
            attr("thirdName", "secondValue", Some("text/grass")),
            attr("fourthName", "secondValue", Some("text/grass")),
        ];
        assert!(!are_preview_attributes_equal(&first, &second));
    }

    #[test]
    fn returns_false_for_duplicate_names() {
        let first = vec![
            attr("secondName", "secondValue", Some("text/grass")),
            attr("secondName", "secondValue", Some("text/grass")),
        ];
        let second = vec![attr("secondName", "secondValue", Some("text/grass"))];
        assert!(!are_preview_attributes_equal(&first, &second));
    }

    #[test]
    fn order_does_not_matter_when_names_unique() {
        let first = vec![attr("alpha", "1", None), attr("beta", "2", None)];
        let second = vec![attr("beta", "2", None), attr("alpha", "1", None)];
        assert!(are_preview_attributes_equal(&first, &second));
    }

    #[test]
    fn mime_type_none_matches_only_none() {
        let with_mime = vec![attr("name", "value", Some("text/plain"))];
        let no_mime = vec![attr("name", "value", None)];
        assert!(!are_preview_attributes_equal(&with_mime, &no_mime));
    }
}
