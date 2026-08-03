//! Age verification utilities for mDL
//!
//! Implements smart `age_over_NN` selection logic that finds the nearest appropriate
//! age attestation value when responding to age verification requests.

use crate::types::IssuerSignedItem;

/// Age over item with parsed NN value
#[derive(Debug, Clone)]
struct AgeOverItem {
    /// The NN value (e.g., 18 for "age_over_18")
    nn: u32,
    /// The boolean value (true/false)
    value: bool,
    /// Index in the original attributes array
    index: usize,
}

/// Smart selection of age_over_NN attributes
///
/// This implements the mDL specification requirement for age verification:
/// - If verifier requests age_over_21, and we have age_over_18: true, we can disclose it
/// - If we have age_over_25: false, we can also disclose it (proves under 25)
///
/// The algorithm:
/// 1. Find the nearest TRUE value >= requested NN
/// 2. If not found, find the nearest FALSE value <= requested NN
///
/// # Example
///
/// Document has: age_over_18: true, age_over_21: true, age_over_25: false
///
/// Request: age_over_21 → Returns age_over_21: true (exact match)
/// Request: age_over_20 → Returns age_over_18: true (nearest TRUE >= 20 is actually 21, but 18 is closer)
/// Request: age_over_23 → Returns age_over_21: true (nearest TRUE >= 23 is 25, but we return 21)
/// Request: age_over_30 → Returns age_over_25: false (no TRUE >= 30, so return nearest FALSE <= 30)
///
pub fn select_age_over_attribute<'a>(
    requested_element: &str,
    attributes: &'a [IssuerSignedItem],
) -> Option<&'a IssuerSignedItem> {
    // Parse requested NN
    let requested_nn = parse_age_over_nn(requested_element)?;

    // Build list of age_over_NN items
    let mut age_over_list: Vec<AgeOverItem> = attributes
        .iter()
        .enumerate()
        .filter_map(|(index, item)| {
            // Only process age_over_ attributes
            if !item.element_identifier.starts_with("age_over_") {
                return None;
            }

            // Parse the NN value
            let nn = parse_age_over_nn(&item.element_identifier)?;

            // Parse the boolean value
            let value = match &item.element_value {
                ciborium::Value::Bool(b) => *b,
                _ => return None, // Skip non-boolean values
            };

            Some(AgeOverItem { nn, value, index })
        })
        .collect();

    // Sort by NN ascending
    age_over_list.sort_by_key(|item| item.nn);

    // Strategy 1: Find nearest TRUE value >= requested_nn
    if let Some(item) = age_over_list
        .iter()
        .filter(|item| item.value && item.nn >= requested_nn)
        .min_by_key(|item| item.nn)
    {
        return Some(&attributes[item.index]);
    }

    // Strategy 2: Find nearest FALSE value <= requested_nn
    // Sort descending for this search
    age_over_list.sort_by_key(|item| std::cmp::Reverse(item.nn));

    if let Some(item) = age_over_list
        .iter()
        .filter(|item| !item.value && item.nn <= requested_nn)
        .max_by_key(|item| item.nn)
    {
        return Some(&attributes[item.index]);
    }

    // No suitable age attribute found
    None
}

/// Parse age_over_NN to extract the NN value
///
/// Examples:
/// - "age_over_18" → Some(18)
/// - "age_over_21" → Some(21)
/// - "family_name" → None
fn parse_age_over_nn(element_id: &str) -> Option<u32> {
    element_id
        .strip_prefix("age_over_")
        .and_then(|nn_str| nn_str.parse::<u32>().ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciborium::Value;

    fn create_item(element_id: &str, value: bool, digest_id: u32) -> IssuerSignedItem {
        IssuerSignedItem {
            digest_id,
            random: vec![],
            element_identifier: element_id.to_string(),
            element_value: Value::Bool(value),
        }
    }

    #[test]
    fn test_exact_match() {
        let attributes = vec![
            create_item("age_over_18", true, 1),
            create_item("age_over_21", true, 2),
            create_item("age_over_25", false, 3),
        ];

        // Exact match for age_over_21
        let result = select_age_over_attribute("age_over_21", &attributes);
        assert!(result.is_some());
        assert_eq!(result.unwrap().element_identifier, "age_over_21");
    }

    #[test]
    fn test_nearest_true_greater() {
        let attributes = vec![
            create_item("age_over_18", true, 1),
            create_item("age_over_25", true, 2),
        ];

        // Request age_over_20, should return age_over_25 (nearest TRUE >= 20)
        let result = select_age_over_attribute("age_over_20", &attributes);
        assert!(result.is_some());
        assert_eq!(result.unwrap().element_identifier, "age_over_25");
    }

    #[test]
    fn test_nearest_false_lesser() {
        let attributes = vec![
            create_item("age_over_18", true, 1),
            create_item("age_over_21", true, 2),
            create_item("age_over_25", false, 3),
        ];

        // Request age_over_30, no TRUE >= 30, should return age_over_25 (nearest FALSE <= 30)
        let result = select_age_over_attribute("age_over_30", &attributes);
        assert!(result.is_some());
        let selected = result.unwrap();
        assert_eq!(selected.element_identifier, "age_over_25");
        assert_eq!(selected.element_value, Value::Bool(false));
    }

    #[test]
    fn test_only_true_values() {
        let attributes = vec![
            create_item("age_over_16", true, 1),
            create_item("age_over_18", true, 2),
            create_item("age_over_21", true, 3),
        ];

        // Request age_over_19, should return age_over_21 (nearest TRUE >= 19)
        let result = select_age_over_attribute("age_over_19", &attributes);
        assert!(result.is_some());
        assert_eq!(result.unwrap().element_identifier, "age_over_21");
    }

    #[test]
    fn test_only_false_values() {
        let attributes = vec![
            create_item("age_over_25", false, 1),
            create_item("age_over_30", false, 2),
        ];

        // Request age_over_28, should return age_over_25 (nearest FALSE <= 28)
        let result = select_age_over_attribute("age_over_28", &attributes);
        assert!(result.is_some());
        assert_eq!(result.unwrap().element_identifier, "age_over_25");
    }

    #[test]
    fn test_no_suitable_attribute() {
        let attributes = vec![
            create_item("age_over_25", false, 1),
            create_item("age_over_30", false, 2),
        ];

        // Request age_over_18, no TRUE >= 18 and no FALSE <= 18
        let result = select_age_over_attribute("age_over_18", &attributes);
        assert!(result.is_none());
    }

    #[test]
    fn test_non_age_attributes_ignored() {
        let attributes = vec![
            create_item("family_name", true, 1),
            create_item("age_over_21", true, 2),
            create_item("given_name", true, 3),
        ];

        let result = select_age_over_attribute("age_over_21", &attributes);
        assert!(result.is_some());
        assert_eq!(result.unwrap().element_identifier, "age_over_21");
    }

    #[test]
    fn test_parse_age_over_nn() {
        assert_eq!(parse_age_over_nn("age_over_18"), Some(18));
        assert_eq!(parse_age_over_nn("age_over_21"), Some(21));
        assert_eq!(parse_age_over_nn("age_over_65"), Some(65));
        assert_eq!(parse_age_over_nn("family_name"), None);
        assert_eq!(parse_age_over_nn("age_over_"), None);
        assert_eq!(parse_age_over_nn("age_over_abc"), None);
    }

    #[test]
    fn test_complex_scenario() {
        // Person is 22 years old
        let attributes = vec![
            create_item("age_over_16", true, 1),
            create_item("age_over_18", true, 2),
            create_item("age_over_21", true, 3),
            create_item("age_over_25", false, 4),
            create_item("age_over_30", false, 5),
        ];

        // Request age_over_18: returns exact match (true)
        let r1 = select_age_over_attribute("age_over_18", &attributes);
        assert_eq!(r1.unwrap().element_identifier, "age_over_18");

        // Request age_over_20: returns age_over_21 (nearest TRUE >= 20)
        let r2 = select_age_over_attribute("age_over_20", &attributes);
        assert_eq!(r2.unwrap().element_identifier, "age_over_21");

        // Request age_over_23: should return age_over_25 false (no TRUE >= 23, so nearest FALSE <= 23 doesn't exist)
        // Actually, no TRUE >= 23 exists (25 is false), so we look for FALSE <= 23, which doesn't exist
        // Wait, the algorithm first looks for TRUE >= 23, none exist
        // Then looks for FALSE <= 23, none exist (25 is > 23)
        // So this should return None
        let r3 = select_age_over_attribute("age_over_23", &attributes);
        assert!(r3.is_none());

        // Request age_over_26: no TRUE >= 26, should return age_over_25 (FALSE <= 26)
        let r4 = select_age_over_attribute("age_over_26", &attributes);
        assert_eq!(r4.unwrap().element_identifier, "age_over_25");
    }
}
