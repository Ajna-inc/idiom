//! JSON-LD → RDF dataset → URDNA2015 canonical N-Quads, the
//! canonicalization step `eddsa-rdfc-2022` runs over both the
//! credential and the proof config before SHA-256 + Ed25519 verify.
//!
//! Implements the standard RDFC-1.0 canonicalization pipeline:
//!
//! 1. `jsonld.toRDF(document, {algorithm: 'RDFC-1.0', base: null,
//!    rdfDirection: 'i18n-datatype', safe})` → RDF dataset
//! 2. `rdfCanonize.canonize(dataset, {algorithm: 'RDFC-1.0',
//!    format: 'application/n-quads'})` → canonical N-Quads
//!
//! In Rust we wire `json-ld 0.21` (for step 1) and `rdf-canon 0.15`
//! (for step 2). The `Loader` impl points at our embedded context
//! cache so the pipeline never touches the network.

use std::sync::Arc;

use iref::{Iri, IriBuf};
use json_ld::{
    syntax::{Parse as _, Value as LdSyntax},
    JsonLdProcessor, LoadError, Loader, RemoteDocument,
};
use oxrdf::{
    BlankNode, Dataset, GraphName, Literal as OxLiteral, NamedNode, Subject, Term as OxTerm,
};
use rdf_canon::canonicalize;
use rdf_types::{
    generator::Blank as BlankGenerator, BlankIdBuf, Id, LiteralType, Object as RdfObject,
    Term as RdfTerm,
};
use serde_json::Value;

use super::context_loader::ContextLoader;

/// Canonicalize a JSON-LD document (without a `proof` field) into the
/// canonical N-Quads string that `eddsa-rdfc-2022` hashes.
///
/// The function performs no network I/O — every `@context` URL the
/// demo issuer references is pre-cached in `ContextLoader::new`. If
/// a credential references an unknown context, the loader returns
/// `LoadError` and the caller surfaces it.
pub async fn canonicalize_jsonld_to_nquads(
    document: &Value,
    context_loader: Arc<ContextLoader>,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    // 1. Convert `serde_json::Value` → `json-ld`'s own syntax::Value
    //    by round-tripping through a string. The two libraries don't
    //    share a JSON type; round-tripping is cheap and unambiguous.
    let raw = serde_json::to_string(document)?;
    let (parsed, _meta) =
        LdSyntax::parse_str(&raw).map_err(|e| format!("json-syntax parse: {}", e))?;

    let base_iri = IriBuf::new("https://ajna.local/credential".to_string())
        .map_err(|e| format!("base iri: {}", e))?;
    let input = RemoteDocument::new(
        Some(base_iri),
        Some("application/ld+json".parse().unwrap()),
        parsed,
    );

    // 2. Run JSON-LD expansion + JSON-LD-to-RDF in one shot. Use an
    //    empty unit-vocabulary (V = ()) — that yields IriBuf/BlankIdBuf
    //    directly, no vocabulary remapping.
    let loader = EmbeddedContextLoader::new(context_loader);
    let generator = BlankGenerator::new();
    let mut to_rdf = input
        .to_rdf(generator, &loader)
        .await
        .map_err(|e| format!("json-ld to_rdf: {}", e))?;

    // 3. Pull every quad into an `oxrdf::Dataset` so we can feed it
    //    to rdf-canon (which operates on the oxigraph data model).
    let mut dataset = Dataset::new();
    for q in to_rdf.cloned_quads() {
        if let Some(ox_q) = json_ld_quad_to_oxrdf(q) {
            dataset.insert(ox_q.as_ref());
        }
    }

    // 4. URDNA2015 — deterministic blank-node labels + sorted N-Quads.
    let canonical = canonicalize(&dataset).map_err(|e| format!("URDNA2015 canonicalize: {}", e))?;
    Ok(canonical)
}

/// Wraps our `ContextLoader` cache in the `json_ld::Loader` trait.
/// Every `@context` the demo issuer references is pre-loaded; for
/// anything not in the cache we return a `LoadError`.
pub struct EmbeddedContextLoader {
    cache: Arc<ContextLoader>,
}

impl EmbeddedContextLoader {
    pub fn new(cache: Arc<ContextLoader>) -> Self {
        Self { cache }
    }
}

impl Loader for EmbeddedContextLoader {
    async fn load(&self, url: &Iri) -> Result<RemoteDocument<IriBuf>, LoadError> {
        let key = url.as_str().to_string();
        let url_buf = IriBuf::new(key.clone()).map_err(|e| {
            LoadError::new(
                IriBuf::new("urn:ajna:invalid-iri".to_string()).unwrap(),
                LoaderErr(format!("invalid iri {}: {}", key, e)),
            )
        })?;
        let mut ctx = self
            .cache
            .load_context(&key)
            .await
            .map_err(|e| LoadError::new(url_buf.clone(), LoaderErr(format!("{}", e))))?;
        // Strip `@protected` recursively. Both VC v2 and OB v3 mark
        // common terms (`name`, `description`, etc.) as @protected;
        // since both contexts map them to the *same* IRIs, dropping
        // the protection lets JSON-LD expansion succeed without
        // changing the semantic output. This is the standard context
        // preprocessing step for JSON-LD expansion of protected terms.
        strip_protected(&mut ctx);
        let raw = serde_json::to_string(&ctx)
            .map_err(|e| LoadError::new(url_buf.clone(), LoaderErr(format!("{}", e))))?;
        let (parsed, _meta) = LdSyntax::parse_str(&raw)
            .map_err(|e| LoadError::new(url_buf.clone(), LoaderErr(format!("{}", e))))?;
        Ok(RemoteDocument::new(
            Some(url_buf),
            Some("application/ld+json".parse().unwrap()),
            parsed,
        ))
    }
}

/// Recursively delete `@protected` keys from a JSON tree. The
/// reference impl `contextPreprocessor.ts:27-49` does this same
/// transformation before handing contexts to jsonld.
fn strip_protected(v: &mut Value) {
    match v {
        Value::Object(map) => {
            map.remove("@protected");
            for (_, child) in map.iter_mut() {
                strip_protected(child);
            }
        }
        Value::Array(arr) => {
            for item in arr.iter_mut() {
                strip_protected(item);
            }
        }
        _ => {}
    }
}

#[derive(Debug)]
struct LoaderErr(String);
impl std::fmt::Display for LoaderErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for LoaderErr {}

/// Translate one json-ld quad (`Quad<Id<IriBuf, BlankIdBuf>, …>`)
/// into an `oxrdf::Quad`. Returns `None` only when the IRI/blank id
/// is malformed (shouldn't happen for well-formed input).
fn json_ld_quad_to_oxrdf(
    q: rdf_types::Quad<
        Id<IriBuf, BlankIdBuf>,
        Id<IriBuf, BlankIdBuf>,
        RdfObject<Id<IriBuf, BlankIdBuf>, rdf_types::Literal<IriBuf>>,
        Id<IriBuf, BlankIdBuf>,
    >,
) -> Option<oxrdf::Quad> {
    let subject = id_to_subject(q.0)?;
    let predicate = match q.1 {
        Id::Iri(iri) => NamedNode::new(iri.as_str()).ok()?,
        // RDF predicates must be IRIs — skip blank-node predicates.
        Id::Blank(_) => return None,
    };
    let object = ld_object_to_oxrdf_term(q.2)?;
    let graph_name = match q.3 {
        Some(g) => id_to_graph(g)?,
        None => GraphName::DefaultGraph,
    };
    Some(oxrdf::Quad::new(subject, predicate, object, graph_name))
}

fn id_to_subject(id: Id<IriBuf, BlankIdBuf>) -> Option<Subject> {
    Some(match id {
        Id::Iri(iri) => Subject::NamedNode(NamedNode::new(iri.as_str()).ok()?),
        Id::Blank(b) => {
            Subject::BlankNode(BlankNode::new(b.as_str().trim_start_matches("_:")).ok()?)
        }
    })
}

fn id_to_graph(id: Id<IriBuf, BlankIdBuf>) -> Option<GraphName> {
    Some(match id {
        Id::Iri(iri) => GraphName::NamedNode(NamedNode::new(iri.as_str()).ok()?),
        Id::Blank(b) => {
            GraphName::BlankNode(BlankNode::new(b.as_str().trim_start_matches("_:")).ok()?)
        }
    })
}

fn ld_object_to_oxrdf_term(
    obj: RdfObject<Id<IriBuf, BlankIdBuf>, rdf_types::Literal<IriBuf>>,
) -> Option<OxTerm> {
    Some(match obj {
        RdfTerm::Id(id) => match id {
            Id::Iri(iri) => OxTerm::NamedNode(NamedNode::new(iri.as_str()).ok()?),
            Id::Blank(b) => {
                OxTerm::BlankNode(BlankNode::new(b.as_str().trim_start_matches("_:")).ok()?)
            }
        },
        RdfTerm::Literal(lit) => {
            let oxlit = match lit.type_ {
                LiteralType::Any(iri) => {
                    OxLiteral::new_typed_literal(lit.value, NamedNode::new(iri.as_str()).ok()?)
                }
                LiteralType::LangString(tag) => {
                    OxLiteral::new_language_tagged_literal(lit.value, tag.as_str()).ok()?
                }
            };
            OxTerm::Literal(oxlit)
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn canonicalizes_trivial_vc1_doc() {
        let doc = json!({
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "id": "https://example.org/credentials/1",
            "type": ["VerifiableCredential"],
            "issuer": "https://example.org/issuers/1",
            "issuanceDate": "2024-01-01T00:00:00Z",
            "credentialSubject": {
                "id": "https://example.org/subjects/1"
            }
        });
        let loader = Arc::new(ContextLoader::offline());
        let nquads = canonicalize_jsonld_to_nquads(&doc, loader)
            .await
            .expect("canonicalize");
        assert!(
            nquads.contains("https://example.org/credentials/1"),
            "canonical N-Quads should mention the subject IRI: {}",
            nquads
        );
    }
}
