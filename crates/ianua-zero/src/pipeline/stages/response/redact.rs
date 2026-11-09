//! `Redact`: classified fields taken out of a JSON answer before the client
//! sees it, by the tenant's classification rule set.
//!
//! A field whose rule is at or above the stage's class is removed, masked
//! or replaced by a digest keyed by the gateway, as its rule says; a rule
//! asking for encryption,
//! which no key backs, masks. Array elements are read under their parent's
//! path, so a rule for `items.ssn` covers every element's `ssn`.
//!
//! Only a JSON answer has fields to redact; any other answer passes. A JSON
//! answer the stage cannot mask is withheld, never passed on with the
//! fields it exists to hide: one longer than the gateway reads (a body is
//! only rewritten when the whole of it was read), one compressed, one that
//! does not parse, and one whose rule set cannot be read or is not the one
//! the stage names.

use ianua_app::ports::data_classification::RedactionDigest;
use ianua_app::ports::proxy::ResponseStageOutcome;
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::data_classification::classification::{
    ClassificationRuleSet, MASK, RedactionStrategy,
};
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::domains::proxy::request::context::PipelineContext;
use ianua_domain::domains::proxy::request::transform::ResponseMutation;
use ianua_domain::domains::proxy::stages::stage::RedactConfig;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::TenantId;
use serde_json::{Map, Value};

use super::body::{Encoding, encoding, is_json};
use super::{ResponseRead, ResponseStages, unchanged, withheld};

/// A tenant's rule set, as redaction reads it.
type Rules = ClassificationRuleSet<ResolvedTenant>;

/// What redacting one answer applies: the tenant's rules from a level up,
/// and the keyed digest a hashed field is replaced with.
#[derive(Clone, Copy)]
struct Redaction<'a> {
    rules: &'a Rules,
    min: DataClassLevel,
    digest: &'a dyn RedactionDigest,
    tenant: TenantId,
}

impl ResponseStages {
    /// Redacts the classified fields of a JSON answer, or withholds a JSON
    /// answer it cannot redact. Any other answer passes unchanged.
    ///
    /// # Errors
    ///
    /// Never: an answer that cannot be redacted is withheld.
    pub(crate) async fn redact(
        &self,
        config: &RedactConfig,
        read: ResponseRead<'_>,
    ) -> Result<ResponseStageOutcome, DomainError> {
        if let Some(outcome) = unread_json(read) {
            return Ok(outcome);
        }
        let Some(rules) = self.rules_for(config, read.context).await else {
            return Ok(withheld("the classification rule set could not be read"));
        };
        let redaction = Redaction {
            rules: &rules,
            min: config.min_class,
            digest: self.redaction.as_ref(),
            tenant: read.context.tenant_id,
        };
        Ok(redaction.rewrite(read.body.bytes))
    }

    /// The tenant's rule set, when it can be read and is the one the stage
    /// names. `None` otherwise: a stage never redacts by another rule set,
    /// or by none.
    async fn rules_for(&self, config: &RedactConfig, ctx: &PipelineContext) -> Option<Rules> {
        let tenant = ScopedTenant::from_request_host(ctx.tenant_id);
        let found = self
            .within(self.classifications.find(&tenant))
            .await
            .inspect_err(|error| {
                tracing::warn!(%error, "a classification rule set could not be read");
            })
            .ok()??;
        (found.id() == &config.rule_set_id).then_some(found)
    }
}

/// Passes non-JSON answers and refuses JSON whose complete bytes cannot be inspected.
fn unread_json(read: ResponseRead<'_>) -> Option<ResponseStageOutcome> {
    let ResponseRead {
        meta: response,
        body,
        ..
    } = read;
    if !is_json(response) {
        return Some(unchanged("not a JSON answer"));
    }
    if encoding(response) == Encoding::Encoded {
        return Some(withheld(
            "the JSON answer is encoded and cannot be redacted",
        ));
    }
    if !body.is_whole() {
        return Some(withheld(
            "the JSON answer is longer than the gateway reads to redact it",
        ));
    }
    None
}

impl Redaction<'_> {
    /// Rewrites complete JSON using the tenant's rules, withholding an unreadable answer.
    fn rewrite(self, bytes: &[u8]) -> ResponseStageOutcome {
        let Ok(mut answer) = serde_json::from_slice::<Value>(bytes) else {
            return withheld("the JSON answer could not be read");
        };
        let redacted = redact_in(&mut answer, "", self);
        if redacted == 0 {
            return unchanged("no classified field in the answer");
        }
        let Ok(rewritten) = serde_json::to_vec(&answer) else {
            return withheld("the redacted answer could not be written");
        };
        ResponseStageOutcome::Change {
            headers: ResponseMutation::default(),
            body: Some(rewritten),
            reason: format!("redacted {redacted} field(s)"),
        }
    }
}

/// Redacts what `redaction` classifies in `value`, found at `path`.
/// Returns how many fields were redacted.
fn redact_in(value: &mut Value, path: &str, redaction: Redaction<'_>) -> usize {
    match value {
        Value::Object(fields) => redact_fields(fields, path, redaction),
        Value::Array(items) => items
            .iter_mut()
            .map(|item| redact_in(item, path, redaction))
            .sum(),
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => 0,
    }
}

/// Redacts the fields of one object, and what is classified inside those
/// left as they are. A redacted field is not looked into.
fn redact_fields(fields: &mut Map<String, Value>, path: &str, redaction: Redaction<'_>) -> usize {
    let mut redacted = 0;
    let mut removed = Vec::new();
    for (name, field) in fields.iter_mut() {
        let at = field_path(path, name);
        let Some(strategy) = redaction.rules.redaction_at(&at, redaction.min) else {
            redacted += redact_in(field, &at, redaction);
            continue;
        };
        redacted += 1;
        match strategy {
            RedactionStrategy::Remove => removed.push(name.clone()),
            RedactionStrategy::Mask | RedactionStrategy::Encrypt => *field = Value::from(MASK),
            RedactionStrategy::Hash => *field = hashed(field, redaction),
        }
    }
    for name in removed {
        fields.remove(&name);
    }
    redacted
}

/// The dotted path of the field `name` inside `parent`.
fn field_path(parent: &str, name: &str) -> String {
    if parent.is_empty() {
        return name.to_owned();
    }
    format!("{parent}.{name}")
}

/// A field's value replaced by the keyed digest of its JSON form: equal
/// values read equal within the tenant, and no value can be found again by
/// hashing guesses, as a plain hash of a social security number could.
fn hashed(value: &Value, redaction: Redaction<'_>) -> Value {
    Value::from(
        redaction
            .digest
            .digest(&redaction.tenant, value.to_string().as_bytes()),
    )
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ianua_app::ports::data_classification::ClassificationStore;
    use ianua_app::test_support::data_classification::FakeClassificationStore;
    use ianua_domain::domains::data_classification::classification::ClassificationRule;
    use ianua_domain::domains::proxy::request::body::{BodyExtent, CapturedBody};
    use ianua_domain::types::{ClassificationRuleSetId, FieldPath};

    use super::*;
    use crate::pipeline::stages::response::fixtures::{
        Fakes, answer, context, is_unchanged, is_withheld, json, replaced,
    };

    fn rule(path: &str, level: DataClassLevel, strategy: RedactionStrategy) -> ClassificationRule {
        ClassificationRule::new(FieldPath::new(path).unwrap(), level, strategy)
    }

    /// A group whose store holds `rules` for the tenant of `ctx`, and the
    /// stage reading that rule set from class `min`.
    async fn holding(
        ctx: &PipelineContext,
        rules: Vec<ClassificationRule>,
        min: DataClassLevel,
    ) -> (Fakes, RedactConfig) {
        let store = FakeClassificationStore::with_rules(ctx.tenant_id, rules);
        let tenant = ScopedTenant::from_request_host(ctx.tenant_id);
        let rule_set_id = *store.find(&tenant).await.unwrap().unwrap().id();
        let fakes = Fakes {
            classifications: Arc::new(store) as Arc<dyn ClassificationStore>,
            ..Fakes::default()
        };
        (
            fakes,
            RedactConfig {
                rule_set_id,
                min_class: min,
            },
        )
    }

    async fn redact(
        fakes: &Fakes,
        config: &RedactConfig,
        read: ResponseRead<'_>,
    ) -> ResponseStageOutcome {
        fakes.stages().redact(config, read).await.unwrap()
    }

    /// A social security number is removed, a card number masked and an
    /// email hashed, in every element of a list, while an internal field
    /// below the stage's class stays.
    #[tokio::test]
    async fn classified_fields_are_redacted_as_their_rules_say() {
        let ctx = context();
        let (fakes, config) = holding(&ctx, user_rules(), DataClassLevel::Confidential).await;
        let body = br#"{"users":[{"ssn":"123-45-6789","card":"4111","email":"ann@acme.com","team":"ops"},{"ssn":"987-65-4321"}]}"#;

        let outcome = redact(
            &fakes,
            &config,
            ResponseRead {
                context: &ctx,
                meta: &json(),
                body: CapturedBody::new(body, BodyExtent::Whole),
            },
        )
        .await;

        let users = &replaced(&outcome).unwrap()["users"];
        assert!(users[0].get("ssn").is_none());
        assert!(users[1].get("ssn").is_none());
        assert_eq!(users[0]["card"], MASK);
        assert_ne!(users[0]["email"], "ann@acme.com");
        assert_eq!(users[0]["team"], "ops");
    }

    /// Classifications exercise every supported replacement and the stage's lower-class cutoff.
    fn user_rules() -> Vec<ClassificationRule> {
        vec![
            rule(
                "users.ssn",
                DataClassLevel::Restricted,
                RedactionStrategy::Remove,
            ),
            rule(
                "users.card",
                DataClassLevel::Confidential,
                RedactionStrategy::Mask,
            ),
            rule(
                "users.email",
                DataClassLevel::Confidential,
                RedactionStrategy::Hash,
            ),
            rule(
                "users.team",
                DataClassLevel::Internal,
                RedactionStrategy::Remove,
            ),
        ]
    }

    /// A hash-classified social security number is replaced with a value
    /// different from both its plaintext and its plain SHA-256 digest.
    #[tokio::test]
    async fn a_hashed_field_is_a_keyed_digest() {
        use base64::Engine as _;
        use sha2::Digest as _;

        let ctx = context();
        let (fakes, config) = holding(
            &ctx,
            vec![rule(
                "ssn",
                DataClassLevel::Restricted,
                RedactionStrategy::Hash,
            )],
            DataClassLevel::Restricted,
        )
        .await;
        let body = br#"{"ssn":"123-45-6789"}"#;

        let outcome = redact(
            &fakes,
            &config,
            ResponseRead {
                context: &ctx,
                meta: &json(),
                body: CapturedBody::new(body, BodyExtent::Whole),
            },
        )
        .await;

        let plain = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(sha2::Sha256::digest(br#""123-45-6789""#));
        let hashed = &replaced(&outcome).unwrap()["ssn"];
        assert_ne!(hashed, &serde_json::Value::from(plain));
        assert_ne!(hashed, "123-45-6789");
    }

    /// A truncated JSON answer containing a classified field is withheld
    /// without producing a replacement body.
    #[tokio::test]
    async fn a_truncated_answer_is_never_rewritten() {
        let ctx = context();
        let (fakes, config) = holding(
            &ctx,
            vec![rule(
                "ssn",
                DataClassLevel::Restricted,
                RedactionStrategy::Remove,
            )],
            DataClassLevel::Confidential,
        )
        .await;

        let outcome = redact(
            &fakes,
            &config,
            ResponseRead {
                context: &ctx,
                meta: &json(),
                body: CapturedBody::new(br#"{"ssn":"123-45-6789","rows":["#, BodyExtent::Prefix),
            },
        )
        .await;

        assert!(is_withheld(&outcome));
        assert!(replaced(&outcome).is_none());
    }

    /// A compressed JSON answer is withheld because the stage cannot inspect its fields.
    #[tokio::test]
    async fn a_compressed_json_answer_is_withheld() {
        let ctx = context();
        let (fakes, config) = hiding_ssn(&ctx).await;
        let gzip = answer(
            200,
            &[
                ("content-type", "application/json"),
                ("content-encoding", "gzip"),
            ],
        );

        let compressed = redact(
            &fakes,
            &config,
            ResponseRead {
                context: &ctx,
                meta: &gzip,
                body: CapturedBody::new(b"\x1f\x8b", BodyExtent::Whole),
            },
        )
        .await;
        assert!(is_withheld(&compressed));
    }

    /// Malformed JSON is withheld even when the tenant's classification rules can be read.
    #[tokio::test]
    async fn an_unreadable_json_answer_is_withheld() {
        let ctx = context();
        let (fakes, config) = hiding_ssn(&ctx).await;
        let unreadable = redact(
            &fakes,
            &config,
            ResponseRead {
                context: &ctx,
                meta: &json(),
                body: CapturedBody::new(b"{\"ssn\":", BodyExtent::Whole),
            },
        )
        .await;
        assert!(is_withheld(&unreadable));
    }

    /// An answer is withheld when the tenant has no classification rule set in the store.
    #[tokio::test]
    async fn an_answer_without_classification_rules_is_withheld() {
        let ctx = context();
        let (_, config) = hiding_ssn(&ctx).await;
        let no_rules = redact(
            &Fakes::default(),
            &config,
            ResponseRead {
                context: &ctx,
                meta: &json(),
                body: CapturedBody::new(b"{}", BodyExtent::Whole),
            },
        )
        .await;

        assert!(is_withheld(&no_rules));
    }

    /// A tenant whose restricted social security field is removed at the confidential threshold.
    async fn hiding_ssn(ctx: &PipelineContext) -> (Fakes, RedactConfig) {
        holding(
            ctx,
            vec![rule(
                "ssn",
                DataClassLevel::Restricted,
                RedactionStrategy::Remove,
            )],
            DataClassLevel::Confidential,
        )
        .await
    }

    /// A JSON answer is withheld when the stage names a different rule set
    /// from the one held by the tenant's store.
    #[tokio::test]
    async fn a_rule_set_other_than_the_one_named_is_not_used() {
        let ctx = context();
        let (fakes, config) = holding(&ctx, Vec::new(), DataClassLevel::Confidential).await;
        let elsewhere = RedactConfig {
            rule_set_id: ClassificationRuleSetId::new(),
            ..config
        };

        let outcome = redact(
            &fakes,
            &elsewhere,
            ResponseRead {
                context: &ctx,
                meta: &json(),
                body: CapturedBody::new(b"{}", BodyExtent::Whole),
            },
        )
        .await;

        assert!(is_withheld(&outcome));
    }

    /// An HTML page has no fields to redact and passes, even read in part.
    #[tokio::test]
    async fn an_answer_that_is_not_json_passes() {
        let ctx = context();
        let (fakes, config) = holding(&ctx, Vec::new(), DataClassLevel::Confidential).await;

        let outcome = redact(
            &fakes,
            &config,
            ResponseRead {
                context: &ctx,
                meta: &answer(200, &[("content-type", "text/html")]),
                body: CapturedBody::new(b"<html>", BodyExtent::Prefix),
            },
        )
        .await;

        assert!(is_unchanged(&outcome));
    }

    /// A JSON answer with nothing classified in it passes as it came.
    #[tokio::test]
    async fn an_answer_with_nothing_classified_passes() {
        let ctx = context();
        let (fakes, config) = holding(
            &ctx,
            vec![rule(
                "ssn",
                DataClassLevel::Restricted,
                RedactionStrategy::Remove,
            )],
            DataClassLevel::Confidential,
        )
        .await;

        let outcome = redact(
            &fakes,
            &config,
            ResponseRead {
                context: &ctx,
                meta: &json(),
                body: CapturedBody::new(br#"{"id":1}"#, BodyExtent::Whole),
            },
        )
        .await;

        assert!(is_unchanged(&outcome));
    }
}
