//! W3C / JWT-VC / SD-JWT DIDComm credential-exchange service.
//!
//! Sibling of the AnonCreds [`super::CredentialExchangeService`], this service
//! drives the same Issue-Credential state machine (offer → request → issue →
//! ack) for the W3C-family formats by delegating attachment signing /
//! verification to injected [`vc::core::CredentialFormatService`] instances
//! (JSON-LD, JWT-VC, SD-JWT VC). It shares the format-agnostic
//! [`CredentialExchangeRecord`] / repository with the AnonCreds path.
//!
//! Wire shape (RFC 0593 style): propose/offer/request carry a
//! `{credential, options}` *detail*; issue carries the signed credential
//! string.

use crate::domain::{CredentialExchangeRole, CredentialExchangeState};
use crate::formats::{CredentialDetail, DidCommCredentialFormat};
use crate::messages::{IssueCredentialMessage, OfferCredentialMessage, RequestCredentialMessage};
use crate::repository::{CredentialExchangeRecord, CredentialExchangeRepositoryTrait};
use crate::{CredentialError, Result};
use didcomm::messaging::OutboundMessage;
use std::collections::HashMap;
use std::sync::Arc;
use vc::core::{
    CredentialFormat, CredentialFormatService, SignCredentialOptions, VerifyCredentialOptions,
    W3cCredential,
};

/// Orchestrates the Issue-Credential protocol for W3C / JWT / SD-JWT formats.
pub struct W3cCredentialExchangeService {
    /// Format services keyed by [`vc::core::CredentialFormat`].
    services: HashMap<CredentialFormat, Arc<dyn CredentialFormatService>>,
    repository: Arc<dyn CredentialExchangeRepositoryTrait>,

    #[cfg(feature = "events")]
    event_bus: Option<Arc<agent_events::EventBus>>,
    #[cfg(feature = "events")]
    agent_id: String,
}

/// Builder for [`W3cCredentialExchangeService`].
pub struct W3cCredentialExchangeServiceBuilder {
    services: HashMap<CredentialFormat, Arc<dyn CredentialFormatService>>,
    repository: Arc<dyn CredentialExchangeRepositoryTrait>,
    #[cfg(feature = "events")]
    events: Option<(Arc<agent_events::EventBus>, String)>,
}

impl W3cCredentialExchangeServiceBuilder {
    /// Register a format service. Keyed by [`CredentialFormatService::format`].
    pub fn with_format_service(mut self, service: Arc<dyn CredentialFormatService>) -> Self {
        self.services.insert(service.format(), service);
        self
    }

    /// Wire the agent event bus so protocol transitions emit
    /// `credential_exchange.state_changed` events.
    #[cfg(feature = "events")]
    pub fn with_event_bus(
        mut self,
        event_bus: Arc<agent_events::EventBus>,
        agent_id: String,
    ) -> Self {
        self.events = Some((event_bus, agent_id));
        self
    }

    pub fn build(self) -> W3cCredentialExchangeService {
        W3cCredentialExchangeService {
            services: self.services,
            repository: self.repository,
            #[cfg(feature = "events")]
            event_bus: self.events.as_ref().map(|(b, _)| b.clone()),
            #[cfg(feature = "events")]
            agent_id: self
                .events
                .map(|(_, id)| id)
                .unwrap_or_else(|| "unknown".to_string()),
        }
    }
}

impl W3cCredentialExchangeService {
    /// Start building a service backed by `repository`.
    pub fn builder(
        repository: Arc<dyn CredentialExchangeRepositoryTrait>,
    ) -> W3cCredentialExchangeServiceBuilder {
        W3cCredentialExchangeServiceBuilder {
            services: HashMap::new(),
            repository,
            #[cfg(feature = "events")]
            events: None,
        }
    }

    /// True when a DIDComm attachment format id maps to a format this service
    /// has a registered [`CredentialFormatService`] for.
    pub fn supports_format_id(&self, format_id: &str) -> bool {
        DidCommCredentialFormat::from_format_id(format_id)
            .map(|f| self.services.contains_key(&f.vc_format()))
            .unwrap_or(false)
    }

    fn service_for(
        &self,
        format: DidCommCredentialFormat,
    ) -> Result<&Arc<dyn CredentialFormatService>> {
        self.services.get(&format.vc_format()).ok_or_else(|| {
            CredentialError::UnsupportedFormat(format.detail_format_id().to_string())
        })
    }

    fn format_of(record: &CredentialExchangeRecord) -> Result<DidCommCredentialFormat> {
        record
            .credential_format
            .as_deref()
            .and_then(DidCommCredentialFormat::from_format_id)
            .ok_or_else(|| {
                CredentialError::UnsupportedFormat(
                    record
                        .credential_format
                        .clone()
                        .unwrap_or_else(|| "<none>".to_string()),
                )
            })
    }

    // ── events ───────────────────────────────────────────────────────────────

    #[cfg(feature = "events")]
    async fn emit_state_changed(
        &self,
        record: &CredentialExchangeRecord,
        previous_state: Option<CredentialExchangeState>,
    ) {
        if let Some(bus) = &self.event_bus {
            let payload = crate::events::CredentialStateChangedPayload {
                credential_exchange_record: record.clone(),
                previous_state,
            };
            let meta = agent_events::EventMetadata::for_tenant(&self.agent_id);
            let _ = bus.emit(&meta, payload).await;
        }
    }

    #[cfg(not(feature = "events"))]
    async fn emit_state_changed(
        &self,
        _record: &CredentialExchangeRecord,
        _previous_state: Option<CredentialExchangeState>,
    ) {
    }

    // ── lookups ──────────────────────────────────────────────────────────────

    pub async fn find_exchange_by_id(&self, id: &str) -> Result<Option<CredentialExchangeRecord>> {
        self.repository.find_by_id(id).await
    }

    pub async fn find_exchange_by_thread_id(
        &self,
        thread_id: &str,
    ) -> Result<Option<CredentialExchangeRecord>> {
        self.repository.find_by_thread_id(thread_id).await
    }

    pub fn repository(&self) -> &Arc<dyn CredentialExchangeRepositoryTrait> {
        &self.repository
    }

    // ── issuer: offer ────────────────────────────────────────────────────────

    /// Create a credential offer (issuer side). `detail` carries the unsigned
    /// credential + proof options that will be signed at issue time.
    pub async fn create_offer(
        &self,
        connection_id: Option<&str>,
        format: DidCommCredentialFormat,
        detail: CredentialDetail,
    ) -> Result<(CredentialExchangeRecord, OfferCredentialMessage)> {
        // Fail fast if we can't sign this format.
        self.service_for(format)?;

        let offer_json = serde_json::to_string(&detail)?;
        let offer_msg =
            OfferCredentialMessage::new_with_format(offer_json.clone(), format.detail_format_id());

        let mut record = CredentialExchangeRecord::new(
            CredentialExchangeRole::Issuer,
            CredentialExchangeState::OfferSent,
            offer_msg.thread_id.clone(),
        );
        record.credential_format = Some(format.detail_format_id().to_string());
        record.credential_offer_json = Some(offer_json);
        if let Some(conn_id) = connection_id {
            record.set_connection_id(conn_id.to_string());
        }

        self.repository.save(&record).await?;
        self.emit_state_changed(&record, None).await;
        Ok((record, offer_msg))
    }

    // ── holder: store inbound offer + accept ─────────────────────────────────

    /// Store an inbound offer (holder side) → `OfferReceived`. Idempotent by
    /// thread id.
    pub async fn store_offer(
        &self,
        connection_id: Option<&str>,
        offer: &OfferCredentialMessage,
    ) -> Result<CredentialExchangeRecord> {
        if let Some(existing) = self.repository.find_by_thread_id(&offer.thread_id).await? {
            return Ok(existing);
        }
        let format_id = offer
            .format_id()
            .ok_or_else(|| CredentialError::InvalidAttachmentFormat("missing format".into()))?;

        let mut record = CredentialExchangeRecord::new(
            CredentialExchangeRole::Holder,
            CredentialExchangeState::OfferReceived,
            offer.thread_id.clone(),
        );
        record.credential_format = Some(format_id.to_string());
        record.credential_offer_json = Some(offer.credential_offer_json.clone());
        if let Some(conn_id) = connection_id {
            record.set_connection_id(conn_id.to_string());
        }

        self.repository.save(&record).await?;
        self.emit_state_changed(&record, None).await;
        Ok(record)
    }

    /// Accept a stored offer (holder side): echo the credential detail back as a
    /// request (RFC 0593 `createRequest`) → `RequestSent`.
    pub async fn accept_offer(&self, exchange_id: &str) -> Result<RequestCredentialMessage> {
        let mut record = self
            .repository
            .find_by_id(exchange_id)
            .await?
            .ok_or_else(|| CredentialError::NotFound(exchange_id.to_string()))?;

        if record.state != CredentialExchangeState::OfferReceived {
            return Err(CredentialError::InvalidState {
                expected: vec![CredentialExchangeState::OfferReceived],
                actual: record.state,
            });
        }
        if record.role != CredentialExchangeRole::Holder {
            return Err(CredentialError::InvalidRole {
                expected: CredentialExchangeRole::Holder,
                actual: record.role,
            });
        }

        let format = Self::format_of(&record)?;
        let offer_json = record.credential_offer_json.clone().ok_or_else(|| {
            CredentialError::Protocol("No credential offer stored on exchange".to_string())
        })?;

        let request_msg = RequestCredentialMessage::new_with_format(
            record.thread_id.clone(),
            offer_json.clone(),
            format.detail_format_id(),
        );

        record.credential_request_json = Some(offer_json);
        record.update_state(CredentialExchangeState::RequestSent);
        self.repository.update(&record).await?;
        self.emit_state_changed(&record, Some(CredentialExchangeState::OfferReceived))
            .await;
        Ok(request_msg)
    }

    // ── issuer: store request + issue ────────────────────────────────────────

    /// Store an inbound request (issuer side) → `RequestReceived`.
    pub async fn store_request(
        &self,
        exchange_id: &str,
        credential_request_json: &str,
    ) -> Result<()> {
        let mut record = self
            .repository
            .find_by_id(exchange_id)
            .await?
            .ok_or_else(|| CredentialError::NotFound(exchange_id.to_string()))?;

        if record.state != CredentialExchangeState::OfferSent {
            return Err(CredentialError::InvalidState {
                expected: vec![CredentialExchangeState::OfferSent],
                actual: record.state,
            });
        }

        record.credential_request_json = Some(credential_request_json.to_string());
        record.update_state(CredentialExchangeState::RequestReceived);
        self.repository.update(&record).await?;
        self.emit_state_changed(&record, Some(CredentialExchangeState::OfferSent))
            .await;
        Ok(())
    }

    /// Accept a request and issue the credential (issuer side): sign the offered
    /// credential with the format service → `CredentialIssued`.
    ///
    /// `key_id` overrides the signing key; when `None`, the detail's
    /// `options.verificationMethod` is used, falling back to the credential's
    /// `issuer` id.
    pub async fn accept_request(
        &self,
        exchange_id: &str,
        key_id: Option<String>,
    ) -> Result<OutboundMessage> {
        let mut record = self
            .repository
            .find_by_id(exchange_id)
            .await?
            .ok_or_else(|| CredentialError::NotFound(exchange_id.to_string()))?;

        if record.state != CredentialExchangeState::RequestReceived {
            return Err(CredentialError::InvalidState {
                expected: vec![CredentialExchangeState::RequestReceived],
                actual: record.state,
            });
        }
        if record.role != CredentialExchangeRole::Issuer {
            return Err(CredentialError::InvalidRole {
                expected: CredentialExchangeRole::Issuer,
                actual: record.role,
            });
        }

        let format = Self::format_of(&record)?;
        let service = self.service_for(format)?;

        // Sign the credential the issuer offered (authoritative), not whatever
        // the holder echoed.
        let detail_json = record.credential_offer_json.clone().ok_or_else(|| {
            CredentialError::Protocol("No credential offer stored on exchange".to_string())
        })?;
        let detail = CredentialDetail::from_json(&detail_json)?;

        let credential: W3cCredential =
            serde_json::from_value(detail.credential.clone()).map_err(|e| {
                CredentialError::Protocol(format!("offer credential is not a W3C VC: {}", e))
            })?;

        let key_id = key_id
            .or_else(|| detail.verification_method())
            .or_else(|| issuer_id(&detail.credential))
            .ok_or_else(|| {
                CredentialError::Protocol(
                    "No signing key: pass key_id, or set options.verificationMethod / credential.issuer"
                        .to_string(),
                )
            })?;

        let algorithm = detail
            .proof_type()
            .or_else(|| format.default_algorithm().map(|s| s.to_string()));

        let sign_options = SignCredentialOptions {
            format: format.vc_format(),
            key_id,
            algorithm,
            proof_purpose: Some("assertionMethod".to_string()),
            additional: HashMap::new(),
        };

        let signed = service
            .sign_credential(&credential, &sign_options)
            .await
            .map_err(|e| CredentialError::FormatService(e.to_string()))?;

        let issue_msg = IssueCredentialMessage::new_with_format(
            record.thread_id.clone(),
            signed.clone(),
            format.credential_format_id(),
        );
        let didcomm_msg = issue_msg.to_didcomm_message();

        record.credential_json = Some(signed);
        record.update_state(CredentialExchangeState::CredentialIssued);
        self.repository.update(&record).await?;
        self.emit_state_changed(&record, Some(CredentialExchangeState::RequestReceived))
            .await;

        Ok(OutboundMessage {
            message: didcomm_msg,
            to: String::new(),
            from: String::new(),
            connection_id: record.connection_id.clone(),
        })
    }

    // ── holder: process issued credential ────────────────────────────────────

    /// Process a received credential (holder side): verify (best-effort) and
    /// record it → `Done`. Returns the stored credential id.
    pub async fn process_credential(&self, exchange_id: &str, credential: &str) -> Result<String> {
        let mut record = self
            .repository
            .find_by_id(exchange_id)
            .await?
            .ok_or_else(|| CredentialError::NotFound(exchange_id.to_string()))?;

        if record.state != CredentialExchangeState::RequestSent {
            return Err(CredentialError::InvalidState {
                expected: vec![CredentialExchangeState::RequestSent],
                actual: record.state,
            });
        }
        if record.role != CredentialExchangeRole::Holder {
            return Err(CredentialError::InvalidRole {
                expected: CredentialExchangeRole::Holder,
                actual: record.role,
            });
        }

        let format = Self::format_of(&record)?;
        // Best-effort verification: log but don't reject storage, mirroring the
        // agent `store_credential` path (structural/crypto verification maturity
        // varies per format).
        if let Ok(service) = self.service_for(format) {
            match service
                .verify_credential(credential, &VerifyCredentialOptions::default())
                .await
            {
                Ok(res) if !res.is_valid => {
                    tracing::warn!(
                        exchange_id = %record.id,
                        errors = ?res.errors,
                        "Issued credential failed verification; storing anyway"
                    );
                }
                Err(e) => {
                    tracing::warn!(exchange_id = %record.id, error = %e, "Verification errored; storing anyway");
                }
                _ => {}
            }
        }

        let credential_id = uuid::Uuid::new_v4().to_string();
        record.credential_json = Some(credential.to_string());
        record.credential_id = Some(credential_id.clone());
        record.update_state(CredentialExchangeState::Done);
        self.repository.update(&record).await?;
        self.emit_state_changed(&record, Some(CredentialExchangeState::RequestSent))
            .await;
        Ok(credential_id)
    }

    /// Process an inbound ack (issuer side) → `Done`. Idempotent.
    pub async fn process_ack(&self, thread_id: &str) -> Result<CredentialExchangeRecord> {
        let mut record = self
            .repository
            .find_by_thread_id(thread_id)
            .await?
            .ok_or_else(|| CredentialError::NotFound(format!("thread_id: {}", thread_id)))?;
        if record.state == CredentialExchangeState::Done {
            return Ok(record);
        }
        let previous = record.state;
        record.update_state(CredentialExchangeState::Done);
        self.repository.update(&record).await?;
        self.emit_state_changed(&record, Some(previous)).await;
        Ok(record)
    }
}

fn issuer_id(credential: &serde_json::Value) -> Option<String> {
    match credential.get("issuer") {
        Some(serde_json::Value::String(s)) => Some(s.clone()),
        Some(serde_json::Value::Object(o)) => {
            o.get("id").and_then(|v| v.as_str()).map(|s| s.to_string())
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repository::CredentialExchangeRepository;
    use async_trait::async_trait;
    use vc::core::{
        CredentialData, CredentialFormat, VerificationResult, W3cCredential, W3cPresentation,
    };

    /// Minimal echo format service: "signs" by tagging the credential JSON and
    /// "verifies" any string it produced.
    struct FakeJsonLd;

    #[async_trait]
    impl CredentialFormatService for FakeJsonLd {
        fn format(&self) -> CredentialFormat {
            CredentialFormat::JsonLd
        }
        async fn sign_credential(
            &self,
            credential: &W3cCredential,
            _o: &SignCredentialOptions,
        ) -> std::result::Result<String, Box<dyn std::error::Error + Send + Sync>> {
            let mut v = serde_json::to_value(credential)?;
            v["proof"] = serde_json::json!({"type": "FakeSig2024"});
            Ok(serde_json::to_string(&v)?)
        }
        async fn verify_credential(
            &self,
            credential: &str,
            _o: &VerifyCredentialOptions,
        ) -> std::result::Result<VerificationResult, Box<dyn std::error::Error + Send + Sync>>
        {
            let cred: W3cCredential = serde_json::from_str(credential)?;
            Ok(VerificationResult::valid(
                CredentialData::V1(cred),
                CredentialFormat::JsonLd,
            ))
        }
        async fn sign_presentation(
            &self,
            _p: &W3cPresentation,
            _o: &SignCredentialOptions,
        ) -> std::result::Result<String, Box<dyn std::error::Error + Send + Sync>> {
            Ok(String::new())
        }
        async fn verify_presentation(
            &self,
            _p: &str,
            _o: &VerifyCredentialOptions,
        ) -> std::result::Result<VerificationResult, Box<dyn std::error::Error + Send + Sync>>
        {
            Ok(VerificationResult::invalid("n/a"))
        }
        fn can_handle(&self, credential: &str) -> bool {
            credential.contains("@context")
        }
    }

    fn service() -> W3cCredentialExchangeService {
        let repo: Arc<dyn CredentialExchangeRepositoryTrait> =
            Arc::new(CredentialExchangeRepository::new());
        W3cCredentialExchangeService::builder(repo)
            .with_format_service(Arc::new(FakeJsonLd))
            .build()
    }

    fn sample_detail() -> crate::formats::CredentialDetail {
        crate::formats::CredentialDetail::new(
            serde_json::json!({
                "@context": ["https://www.w3.org/2018/credentials/v1"],
                "type": ["VerifiableCredential"],
                "issuer": "did:example:issuer",
                "issuanceDate": "2024-01-01T00:00:00Z",
                "credentialSubject": { "id": "did:example:holder", "name": "Alice" }
            }),
            Some(serde_json::json!({ "verificationMethod": "did:example:issuer#key-1" })),
        )
    }

    #[tokio::test]
    async fn jsonld_offer_request_issue_flow() {
        let issuer = service();
        let holder = service();

        // Issuer offers.
        let (irec, offer) = issuer
            .create_offer(
                Some("conn"),
                DidCommCredentialFormat::JsonLd,
                sample_detail(),
            )
            .await
            .unwrap();
        assert_eq!(irec.state, CredentialExchangeState::OfferSent);
        assert_eq!(
            offer.format_id(),
            Some(crate::messages::formats::JSONLD_LD_PROOF_VC_DETAIL)
        );

        // Holder stores + accepts → request.
        let hrec = holder.store_offer(Some("conn"), &offer).await.unwrap();
        assert_eq!(hrec.state, CredentialExchangeState::OfferReceived);
        let request = holder.accept_offer(&hrec.id).await.unwrap();

        // Issuer stores request + issues.
        issuer
            .store_request(&irec.id, &request.credential_request_json)
            .await
            .unwrap();
        let out = issuer.accept_request(&irec.id, None).await.unwrap();
        let issue_msg =
            crate::messages::IssueCredentialMessage::from_didcomm_message(&out.message).unwrap();
        assert!(issue_msg.credential_json.contains("FakeSig2024"));

        // Holder processes issued credential → Done.
        let cred_id = holder
            .process_credential(&hrec.id, &issue_msg.credential_json)
            .await
            .unwrap();
        assert!(!cred_id.is_empty());
        let done = holder.find_exchange_by_id(&hrec.id).await.unwrap().unwrap();
        assert_eq!(done.state, CredentialExchangeState::Done);

        // Issuer ack → Done.
        issuer.process_ack(&irec.thread_id).await.unwrap();
        let idone = issuer.find_exchange_by_id(&irec.id).await.unwrap().unwrap();
        assert_eq!(idone.state, CredentialExchangeState::Done);
    }

    #[tokio::test]
    async fn unsupported_format_rejected() {
        let repo: Arc<dyn CredentialExchangeRepositoryTrait> =
            Arc::new(CredentialExchangeRepository::new());
        let svc = W3cCredentialExchangeService::builder(repo).build(); // no services
        let err = svc
            .create_offer(None, DidCommCredentialFormat::JwtVc, sample_detail())
            .await
            .unwrap_err();
        assert!(matches!(err, CredentialError::UnsupportedFormat(_)));
    }
}
