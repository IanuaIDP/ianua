//! `ResponseTransform`: the domain's [`ResponseMutation`] applied to the
//! answer on its way back.
//!
//! Headers always. The body only when the tenant gave body rules, and only
//! a JSON body read whole and as written: a rule set to drop a field must
//! never let it through because the answer was too long to read or
//! compressed, so such an answer is withheld rather than passed on or
//! rewritten from a fragment. A rule applies to every element of a list
//! along its path, so a rule written for `/users/1` also cleans `/users`.

use ianua_app::ports::proxy::{ResponseMeta, ResponseStageOutcome};
use ianua_domain::domains::proxy::request::body::CapturedBody;
use ianua_domain::domains::proxy::request::transform::{BodyTransform, ResponseMutation};
use serde_json::Value;

use super::body::{Encoding, encoding, is_json};
use super::{ResponseStages, unchanged, withheld};

impl ResponseStages {
    /// Changes the answer's headers as `mutation` says, and its JSON body
    /// when `mutation` has body rules.
    /// An answer whose body rules cannot be applied is withheld.
    pub(crate) fn response_transform(
        &self,
        mutation: &ResponseMutation,
        response: &ResponseMeta,
        body: CapturedBody<'_>,
    ) -> ResponseStageOutcome {
        if mutation.is_empty() {
            return unchanged("nothing to transform");
        }
        let Some(rules) = mutation.body().filter(|rules| !rules.is_empty()) else {
            return headers_only(mutation, "answer headers transformed");
        };
        if !is_json(response) {
            return headers_only(mutation, "not a JSON answer, body left as it is");
        }
        if encoding(response) == Encoding::Encoded || !body.is_whole() {
            return withheld("the JSON answer could not be read whole to transform it");
        }
        transformed_json(mutation, rules, body.bytes)
    }
}

/// Rewrites a complete JSON answer, withholding it if parsing or encoding fails.
fn transformed_json(
    mutation: &ResponseMutation,
    rules: &BodyTransform,
    bytes: &[u8],
) -> ResponseStageOutcome {
    let Ok(mut answer) = serde_json::from_slice::<Value>(bytes) else {
        return withheld("the JSON answer could not be read");
    };
    if !rewrite(&mut answer, rules) {
        return headers_only(mutation, "no field matched the body rules");
    }
    let Ok(rewritten) = serde_json::to_vec(&answer) else {
        return withheld("the transformed answer could not be written");
    };
    ResponseStageOutcome::Change {
        headers: mutation.clone(),
        body: Some(rewritten),
        reason: "answer transformed".to_owned(),
    }
}

/// The header half of `mutation`, the body left as it is.
fn headers_only(mutation: &ResponseMutation, reason: &str) -> ResponseStageOutcome {
    ResponseStageOutcome::Change {
        headers: mutation.clone(),
        body: None,
        reason: reason.to_owned(),
    }
}

/// Applies `rules` to `answer`: removals, then renames. Returns whether
/// any field changed.
fn rewrite(answer: &mut Value, rules: &BodyTransform) -> bool {
    let removed = rules.remove().iter().fold(false, |changed, path| {
        let segments: Vec<&str> = path.segments().collect();
        remove_at(answer, &segments) || changed
    });
    rules.rename().iter().fold(removed, |changed, rename| {
        let segments: Vec<&str> = rename.from().segments().collect();
        rename_at(answer, &segments, rename.to()) || changed
    })
}

/// Applies `change` to every one of `items`, never stopping at the first
/// that changed. Returns whether any did.
fn changed_in_each(items: &mut [Value], mut change: impl FnMut(&mut Value) -> bool) -> bool {
    let mut changed = false;
    for item in items {
        changed |= change(item);
    }
    changed
}

/// Drops the field `path` names, in every element of a list along the
/// way. Returns whether one was there.
fn remove_at(value: &mut Value, path: &[&str]) -> bool {
    let Some((field, rest)) = path.split_first() else {
        return false;
    };
    match value {
        Value::Array(items) => changed_in_each(items, |item| remove_at(item, path)),
        Value::Object(fields) if rest.is_empty() => fields.remove(*field).is_some(),
        Value::Object(fields) => fields
            .get_mut(*field)
            .is_some_and(|inner| remove_at(inner, rest)),
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => false,
    }
}

/// Renames the field `path` names to `to`, keeping its value, in every
/// element of a list along the way. Returns whether one was there.
fn rename_at(value: &mut Value, path: &[&str], to: &str) -> bool {
    let Some((field, rest)) = path.split_first() else {
        return false;
    };
    match value {
        Value::Array(items) => changed_in_each(items, |item| rename_at(item, path, to)),
        Value::Object(fields) if rest.is_empty() => fields
            .remove(*field)
            .map(|kept| fields.insert(to.to_owned(), kept))
            .is_some(),
        Value::Object(fields) => fields
            .get_mut(*field)
            .is_some_and(|inner| rename_at(inner, rest, to)),
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::proxy::request::body::BodyExtent;
    use ianua_domain::domains::proxy::request::transform::{FieldRename, ResponseMutationRules};
    use ianua_domain::types::{FieldPath, HeaderName};

    use super::*;
    use crate::pipeline::stages::response::fixtures::{
        Fakes, answer, is_unchanged, is_withheld, json, replaced,
    };

    fn with_body(rules: BodyTransform) -> ResponseMutation {
        ResponseMutation::configured(ResponseMutationRules {
            body: Some(rules),
            ..ResponseMutationRules::default()
        })
        .unwrap()
    }

    fn removing(paths: &[&str]) -> ResponseMutation {
        with_body(BodyTransform::new(
            paths
                .iter()
                .map(|path| FieldPath::new(*path).unwrap())
                .collect(),
            Vec::new(),
        ))
    }

    fn transform(
        mutation: &ResponseMutation,
        response: &ResponseMeta,
        body: CapturedBody<'_>,
    ) -> ResponseStageOutcome {
        Fakes::default()
            .stages()
            .response_transform(mutation, response, body)
    }

    /// A nested field is removed from every element of a list, and the
    /// rest of each element stays.
    #[test]
    fn a_field_is_removed_from_every_element() {
        let outcome = transform(
            &removing(&["error.stack"]),
            &json(),
            CapturedBody::new(
                br#"[{"error":{"message":"no","stack":"at a"}},{"error":{"stack":"at b"}}]"#,
                BodyExtent::Whole,
            ),
        );

        let body = replaced(&outcome).unwrap();
        assert_eq!(body[0]["error"]["message"], "no");
        assert!(body[0]["error"].get("stack").is_none());
        assert!(body[1]["error"].get("stack").is_none());
    }

    #[test]
    fn a_field_is_renamed_keeping_its_value() {
        let mutation = with_body(BodyTransform::new(
            Vec::new(),
            vec![FieldRename::new(FieldPath::new("id").unwrap(), "identifier").unwrap()],
        ));

        let outcome = transform(
            &mutation,
            &json(),
            CapturedBody::new(br#"{"id":7}"#, BodyExtent::Whole),
        );

        let body = replaced(&outcome).unwrap();
        assert_eq!(body["identifier"], 7);
        assert!(body.get("id").is_none());
    }

    /// A field-removal rule withholds truncated and compressed JSON answers;
    /// the truncated answer produces no replacement body.
    #[test]
    fn an_answer_that_cannot_be_read_whole_is_withheld() {
        let gzip = answer(
            200,
            &[
                ("content-type", "application/json"),
                ("content-encoding", "gzip"),
            ],
        );

        let truncated = transform(
            &removing(&["debug"]),
            &json(),
            CapturedBody::new(br#"{"id":1,"debug":"#, BodyExtent::Prefix),
        );
        let compressed = transform(
            &removing(&["debug"]),
            &gzip,
            CapturedBody::new(b"\x1f\x8b", BodyExtent::Whole),
        );

        assert!(is_withheld(&truncated));
        assert!(replaced(&truncated).is_none());
        assert!(is_withheld(&compressed));
    }

    /// Header rules change the headers and leave the body to stream, even
    /// one read only in part.
    #[test]
    fn a_header_only_transform_never_touches_the_body() {
        let mutation = ResponseMutation::configured(ResponseMutationRules {
            remove_headers: vec![HeaderName::new("x-powered-by").unwrap()],
            ..ResponseMutationRules::default()
        })
        .unwrap();

        let outcome = transform(
            &mutation,
            &json(),
            CapturedBody::new(b"[", BodyExtent::Prefix),
        );

        let ResponseStageOutcome::Change { headers, body, .. } = outcome else {
            panic!("expected the headers to change");
        };
        assert!(body.is_none());
        assert_eq!(headers.remove_headers().len(), 1);
    }

    /// Body rules on an HTML answer leave its body alone.
    #[test]
    fn a_non_json_answer_keeps_its_body() {
        let outcome = transform(
            &removing(&["debug"]),
            &answer(200, &[("content-type", "text/html")]),
            CapturedBody::new(b"<p>debug</p>", BodyExtent::Prefix),
        );

        assert!(matches!(
            outcome,
            ResponseStageOutcome::Change { body: None, .. }
        ));
    }

    #[test]
    fn an_empty_transform_passes() {
        let outcome = transform(
            &ResponseMutation::default(),
            &json(),
            CapturedBody::new(b"{}", BodyExtent::Whole),
        );

        assert!(is_unchanged(&outcome));
    }
}
