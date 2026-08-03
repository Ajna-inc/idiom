/// Compact serialization format for SD-JWT
use super::types::{SdJwtError, SdJwtVc};

/// Compact SD-JWT format handler
pub struct CompactSdJwt;

impl CompactSdJwt {
    /// Convert SD-JWT VC to compact format
    pub fn encode(sd_jwt_vc: &SdJwtVc) -> String {
        sd_jwt_vc.to_compact()
    }

    /// Parse SD-JWT VC from compact format
    pub fn decode(compact: &str) -> Result<SdJwtVc, SdJwtError> {
        SdJwtVc::from_compact(compact)
    }

    /// Validate compact format structure
    pub fn validate_format(compact: &str) -> bool {
        // Must have at least one tilde
        if !compact.contains('~') {
            return false;
        }

        let parts: Vec<&str> = compact.split('~').collect();

        // Must have at least JWT and one separator
        if parts.is_empty() {
            return false;
        }

        // First part should be a JWT (3 dots)
        let jwt = parts[0];
        if jwt.split('.').count() != 3 {
            return false;
        }

        // Last part can be empty (no key binding) or a JWT
        if let Some(last) = parts.last() {
            if !last.is_empty() && last.split('.').count() != 3 {
                return false;
            }
        }

        true
    }

    /// Extract JWT from compact format
    pub fn extract_jwt(compact: &str) -> Result<String, SdJwtError> {
        let parts: Vec<&str> = compact.split('~').collect();

        if parts.is_empty() {
            return Err(SdJwtError::InvalidFormat(
                "Empty compact string".to_string(),
            ));
        }

        Ok(parts[0].to_string())
    }

    /// Extract disclosures from compact format
    pub fn extract_disclosures(compact: &str) -> Result<Vec<String>, SdJwtError> {
        let parts: Vec<&str> = compact.split('~').collect();

        if parts.len() < 2 {
            return Ok(Vec::new());
        }

        // Middle parts are disclosures (skip first and last)
        let disclosures = parts[1..parts.len() - 1]
            .iter()
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect();

        Ok(disclosures)
    }

    /// Extract key binding JWT from compact format
    pub fn extract_key_binding(compact: &str) -> Result<Option<String>, SdJwtError> {
        let parts: Vec<&str> = compact.split('~').collect();

        if parts.len() < 2 {
            return Ok(None);
        }

        let last = parts.last().unwrap();
        if last.is_empty() {
            Ok(None)
        } else {
            Ok(Some(last.to_string()))
        }
    }

    /// Build compact format from components
    pub fn build(jwt: &str, disclosures: &[String], key_binding: Option<&str>) -> String {
        let mut parts = vec![jwt.to_string()];
        parts.extend(disclosures.iter().cloned());

        if let Some(kb) = key_binding {
            parts.push(kb.to_string());
        } else {
            parts.push(String::new());
        }

        parts.join("~")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compact_format_validation() {
        // Valid formats
        assert!(CompactSdJwt::validate_format("eyJ.eyJ.sig~"));
        assert!(CompactSdJwt::validate_format("eyJ.eyJ.sig~disc1~"));
        assert!(CompactSdJwt::validate_format("eyJ.eyJ.sig~disc1~disc2~"));
        assert!(CompactSdJwt::validate_format(
            "eyJ.eyJ.sig~disc1~eyK.eyK.kb~"
        ));

        // Invalid formats
        assert!(!CompactSdJwt::validate_format("no-tildes"));
        assert!(!CompactSdJwt::validate_format("~"));
        assert!(!CompactSdJwt::validate_format("not.jwt~"));
        assert!(!CompactSdJwt::validate_format("eyJ.eyJ.sig~not.kb"));
    }

    #[test]
    fn test_build_and_extract() {
        let jwt = "eyJ.eyJ.sig";
        let disclosures = vec!["disc1".to_string(), "disc2".to_string()];
        let key_binding = Some("eyK.eyK.kb");

        let compact = CompactSdJwt::build(jwt, &disclosures, key_binding);

        assert_eq!(CompactSdJwt::extract_jwt(&compact).unwrap(), jwt);
        assert_eq!(
            CompactSdJwt::extract_disclosures(&compact).unwrap(),
            disclosures
        );
        assert_eq!(
            CompactSdJwt::extract_key_binding(&compact).unwrap(),
            key_binding.map(String::from)
        );
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        let sd_jwt_vc = SdJwtVc {
            jwt: "eyJ.eyJ.sig".to_string(),
            disclosures: vec!["disc1".to_string()],
            key_binding_jwt: Some("eyK.eyK.kb".to_string()),
        };

        let compact = CompactSdJwt::encode(&sd_jwt_vc);
        let decoded = CompactSdJwt::decode(&compact).unwrap();

        assert_eq!(decoded.jwt, sd_jwt_vc.jwt);
        assert_eq!(decoded.disclosures, sd_jwt_vc.disclosures);
        assert_eq!(decoded.key_binding_jwt, sd_jwt_vc.key_binding_jwt);
    }
}
