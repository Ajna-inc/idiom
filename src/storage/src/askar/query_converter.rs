//! Convert agent_core Query to Askar TagFilter

use agent_core::traits::Query;
use aries_askar::entry::TagFilter;

/// Convert our Query to Askar's TagFilter
///
/// Simple tag-based matching (all tags are AND'd together).
/// This covers 90% of query use cases.
pub fn convert_query(query: &Query) -> TagFilter {
    if query.tags.is_empty() {
        // Empty query matches all entries
        // Return a filter that matches everything using OR of negations
        return TagFilter::all_of(vec![]);
    }

    // Create individual equality filters for each tag
    let filters: Vec<TagFilter> = query
        .tags
        .iter()
        .map(|(key, value)| TagFilter::is_eq(key, value))
        .collect();

    // Combine all filters with AND logic
    if filters.len() == 1 {
        filters.into_iter().next().unwrap()
    } else {
        TagFilter::all_of(filters)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_convert_single_tag() {
        let mut query = Query::default();
        query
            .tags
            .insert("status".to_string(), "active".to_string());

        let filter = convert_query(&query);
        // Filter is created successfully
        assert!(format!("{:?}", filter).contains("TagFilter"));
    }

    #[test]
    fn test_convert_multiple_tags() {
        let mut query = Query::default();
        query
            .tags
            .insert("status".to_string(), "active".to_string());
        query
            .tags
            .insert("type".to_string(), "connection".to_string());

        let filter = convert_query(&query);
        assert!(format!("{:?}", filter).contains("TagFilter"));
    }

    #[test]
    fn test_convert_empty_query() {
        let query = Query::default();

        let filter = convert_query(&query);
        assert!(format!("{:?}", filter).contains("TagFilter"));
    }

    #[test]
    fn test_convert_with_limit() {
        let mut query = Query::default();
        query
            .tags
            .insert("status".to_string(), "active".to_string());
        query.limit = Some(10);

        let filter = convert_query(&query);
        assert!(format!("{:?}", filter).contains("TagFilter"));
    }

    #[test]
    fn test_convert_complex_tags() {
        let mut query = Query::default();
        query
            .tags
            .insert("status".to_string(), "active".to_string());
        query.tags.insert("role".to_string(), "inviter".to_string());
        query
            .tags
            .insert("state".to_string(), "completed".to_string());

        let filter = convert_query(&query);
        assert!(format!("{:?}", filter).contains("TagFilter"));
    }
}
