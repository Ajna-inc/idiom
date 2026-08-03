use std::collections::HashMap;

use crate::domain::instance::Participant;
use crate::domain::template::AttributeSpec;
use crate::error::Result;

/// Resolves credential/proof attributes from workflow context using an attribute plan.
pub struct AttributePlanner;

impl AttributePlanner {
    /// Materialize attribute values from an attribute plan.
    pub fn resolve(
        plan: &HashMap<String, AttributeSpec>,
        context: &serde_json::Value,
        participants: &HashMap<String, Participant>,
        artifacts: &serde_json::Value,
    ) -> Result<HashMap<String, serde_json::Value>> {
        let mut result = HashMap::new();

        // Resolution is lenient: a missing/unresolvable attribute yields Null
        // (stringified to "" downstream), never a hard error. The `required`
        // flag is metadata for the builder/UI, not enforced here — matching the
        // reference plugin's `materialize` (`str(val) if val is not None else ""`).
        // Enforcing it here would reject legitimate happy-path issuance where a
        // field is simply absent from the collected context.
        for (attr_name, spec) in plan {
            let value = match spec {
                AttributeSpec::Context { path, .. } => {
                    resolve_dot_path(context, path).unwrap_or(serde_json::Value::Null)
                }
                AttributeSpec::Static { value, .. } => value.clone(),
                AttributeSpec::Compute { expr, .. } => {
                    let env = serde_json::json!({
                        "context": context,
                        "participants": participants,
                        "artifacts": artifacts,
                    });
                    evaluate_jmespath(expr, &env).unwrap_or(serde_json::Value::Null)
                }
            };
            result.insert(attr_name.clone(), value);
        }

        Ok(result)
    }
}

/// Resolve a dot-separated path in a JSON value (e.g., "form.name" → context.form.name).
fn resolve_dot_path(value: &serde_json::Value, path: &str) -> Option<serde_json::Value> {
    let mut current = value;
    for segment in path.split('.') {
        {
            let v = current.get(segment)?;
            current = v
        }
    }
    Some(current.clone())
}

/// Evaluate a JMESPath expression and return the result as a JSON value.
fn evaluate_jmespath(expr: &str, env: &serde_json::Value) -> Option<serde_json::Value> {
    let compiled = jmespath::compile(expr).ok()?;
    let data = jmespath::Variable::from_json(&serde_json::to_string(env).ok()?).ok()?;
    let result = compiled.search(&data).ok()?;
    // Convert jmespath::Variable back to serde_json::Value
    let json_str = serde_json::to_string(&result).ok()?;
    serde_json::from_str(&json_str).ok()
}
