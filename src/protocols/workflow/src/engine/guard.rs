use std::collections::HashMap;

use jmespath;
use tracing;

use crate::domain::instance::Participant;

/// Evaluates JMESPath guard expressions against workflow environment.
pub struct GuardEvaluator;

impl GuardEvaluator {
    /// Evaluate a JMESPath guard expression.
    ///
    /// Returns `true` if:
    /// - No guard expression is provided (always passes)
    /// - The expression evaluates to a truthy value
    ///
    /// Returns `false` if:
    /// - The expression evaluates to a falsy value
    /// - The expression fails to compile or evaluate
    pub fn eval(
        expr: Option<&str>,
        context: &serde_json::Value,
        participants: &HashMap<String, Participant>,
        artifacts: &serde_json::Value,
    ) -> bool {
        let Some(expr) = expr else {
            return true;
        };

        if expr.is_empty() {
            return true;
        }

        let env = serde_json::json!({
            "context": context,
            "participants": participants,
            "artifacts": artifacts,
        });

        match jmespath::compile(expr) {
            Ok(compiled) => {
                let data =
                    jmespath::Variable::from_json(&serde_json::to_string(&env).unwrap_or_default())
                        .unwrap_or(jmespath::Variable::Null);
                match compiled.search(&data) {
                    Ok(result) => is_truthy(&result),
                    Err(e) => {
                        tracing::warn!("Guard evaluation failed for '{}': {}", expr, e);
                        false
                    }
                }
            }
            Err(e) => {
                tracing::warn!("Guard compilation failed for '{}': {}", expr, e);
                false
            }
        }
    }
}

/// Determine if a JMESPath result is "truthy".
fn is_truthy(value: &jmespath::Variable) -> bool {
    match value {
        jmespath::Variable::Null => false,
        jmespath::Variable::Bool(b) => *b,
        jmespath::Variable::String(s) => !s.is_empty(),
        jmespath::Variable::Number(n) => {
            // Non-zero numbers are truthy
            n.as_f64().map(|f| f != 0.0).unwrap_or(false)
        }
        jmespath::Variable::Array(a) => !a.is_empty(),
        jmespath::Variable::Object(o) => !o.is_empty(),
        jmespath::Variable::Expref(_) => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_participants() -> HashMap<String, Participant> {
        HashMap::new()
    }

    #[test]
    fn test_no_guard_passes() {
        let ctx = serde_json::json!({});
        let artifacts = serde_json::json!({});
        assert!(GuardEvaluator::eval(
            None,
            &ctx,
            &empty_participants(),
            &artifacts
        ));
    }

    #[test]
    fn test_empty_guard_passes() {
        let ctx = serde_json::json!({});
        let artifacts = serde_json::json!({});
        assert!(GuardEvaluator::eval(
            Some(""),
            &ctx,
            &empty_participants(),
            &artifacts
        ));
    }

    #[test]
    fn test_truthy_context_value() {
        let ctx = serde_json::json!({"approved": true});
        let artifacts = serde_json::json!({});
        assert!(GuardEvaluator::eval(
            Some("context.approved"),
            &ctx,
            &empty_participants(),
            &artifacts,
        ));
    }

    #[test]
    fn test_falsy_context_value() {
        let ctx = serde_json::json!({"approved": false});
        let artifacts = serde_json::json!({});
        assert!(!GuardEvaluator::eval(
            Some("context.approved"),
            &ctx,
            &empty_participants(),
            &artifacts,
        ));
    }

    #[test]
    fn test_missing_path_is_falsy() {
        let ctx = serde_json::json!({});
        let artifacts = serde_json::json!({});
        assert!(!GuardEvaluator::eval(
            Some("context.nonexistent"),
            &ctx,
            &empty_participants(),
            &artifacts,
        ));
    }
}
