//! What a notification is posted as, for each kind of destination: a Slack
//! message, a Teams card, or a signed JSON body for a webhook.
//!
//! Slack and Teams show the severity, the title and the body. A webhook
//! gets the notification's facts as JSON, signed as Standard Webhooks lays
//! it out under the notification's id, so its receiver can check the post
//! came from the platform and drop a repeat of one it already took.

use ianua_domain::domains::notifications::notification::Notification;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::Text;
use serde_json::{Value, json};
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;

use crate::http::signing::SignedHeaders;

/// One post, ready to send.
pub(crate) struct Message {
    /// The JSON body.
    pub(crate) body: Vec<u8>,
    /// The signature headers, for a webhook.
    pub(crate) signed: Option<SignedHeaders>,
}

/// `notification` as a Slack message.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when it cannot be written out.
pub(crate) fn slack(notification: &Notification) -> Result<Message, DomainError> {
    let text = escaped_for_slack(&headline(notification));
    let body = json!({ "text": text });
    unsigned(&body)
}

/// `notification` as a Teams Adaptive Card, which both Teams connectors
/// and the Power Automate workflows that replace them take.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when it cannot be written out.
pub(crate) fn teams(notification: &Notification) -> Result<Message, DomainError> {
    let mut blocks = vec![json!({
        "type": "TextBlock",
        "text": headline_title(notification),
        "weight": "Bolder",
        "wrap": true,
    })];
    if let Some(text) = notification.body() {
        blocks.push(json!({ "type": "TextBlock", "text": text.as_str(), "wrap": true }));
    }
    let body = json!({
        "type": "message",
        "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive",
            "content": {
                "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                "type": "AdaptiveCard",
                "version": "1.4",
                "body": blocks,
            },
        }],
    });
    unsigned(&body)
}

/// `notification` as the JSON a webhook receives, signed with `secret`
/// under the notification's id at the time of the post.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when it cannot be written out or
/// signed.
pub(crate) fn webhook(
    notification: &Notification,
    secret: &Secret,
) -> Result<Message, DomainError> {
    let created_at = notification
        .created_at()
        .format(&Rfc3339)
        .map_err(DomainError::infra)?;
    let resource: Option<Uuid> = notification.resource_id().into();
    let body = serde_json::to_vec(&json!({
        "id": notification.id().to_string(),
        "type": notification.event_type().as_str(),
        "category": notification.category().as_str(),
        "severity": notification.severity().as_str(),
        "title": notification.title().as_str(),
        "body": notification.body().map(Text::as_str),
        "resource_id": resource.map(|id| id.to_string()),
        "created_at": created_at,
    }))
    .map_err(DomainError::infra)?;
    let signed = SignedHeaders::of(
        notification.id().to_string(),
        ianua_domain::shared::clock::now(),
        &body,
        std::slice::from_ref(secret),
    )?;
    Ok(Message {
        body,
        signed: Some(signed),
    })
}

/// A post of `body` with no signature.
fn unsigned(body: &Value) -> Result<Message, DomainError> {
    Ok(Message {
        body: serde_json::to_vec(body).map_err(DomainError::infra)?,
        signed: None,
    })
}

/// The severity and title, such as `[critical] Signing key rotated`.
fn headline_title(notification: &Notification) -> String {
    format!(
        "[{}] {}",
        notification.severity().as_str(),
        notification.title().as_str()
    )
}

/// The headline, with the body on the line below when there is one.
fn headline(notification: &Notification) -> String {
    let title = headline_title(notification);
    match notification.body() {
        Some(text) => format!("{title}\n{}", text.as_str()),
        None => title,
    }
}

/// `text` with the three characters Slack reads as markup escaped, so a
/// name such as `<!channel>` in a title cannot ping a whole channel.
fn escaped_for_slack(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::notifications::notification::{
        AboutResource, CreateNotificationParams,
    };
    use ianua_domain::domains::notifications::reach::ToldAs;
    use ianua_domain::domains::notifications::severity::NotificationSeverity;
    use ianua_domain::types::{EventType, Label, NotificationId};

    use super::*;

    fn titled(title: &str) -> Notification {
        Notification::create(CreateNotificationParams {
            id: NotificationId::new(),
            event_type: EventType::parse("tenant.provisioned").unwrap(),
            severity: NotificationSeverity::Info,
            title: Label::new("title", title).unwrap(),
            body: Some(Text::new("body", "Acme is ready").unwrap()),
            resource_id: AboutResource::Nothing,
            told_as: ToldAs::Overseer,
        })
    }

    fn json_of(message: &Message) -> Value {
        serde_json::from_slice(&message.body).unwrap()
    }

    /// A Slack post shows the severity, the title and the body as text.
    #[test]
    fn a_slack_post_shows_severity_title_and_body() {
        let message = slack(&titled("Tenant provisioned")).unwrap();

        assert_eq!(
            json_of(&message)["text"],
            json!("[info] Tenant provisioned\nAcme is ready")
        );
        assert!(message.signed.is_none());
    }

    /// A title containing `<!channel>` appears with escaped angle brackets
    /// in the Slack message text.
    #[test]
    fn slack_markup_in_a_title_is_escaped() {
        let message = slack(&titled("Hello <!channel>")).unwrap();

        let text = json_of(&message)["text"].as_str().unwrap().to_owned();
        assert!(text.contains("&lt;!channel&gt;"), "{text}");
    }

    /// A Teams post is an Adaptive Card holding the headline and the body.
    #[test]
    fn a_teams_post_is_an_adaptive_card() {
        let message = teams(&titled("Tenant provisioned")).unwrap();

        let card = &json_of(&message)["attachments"][0];
        assert_eq!(
            card["contentType"],
            json!("application/vnd.microsoft.card.adaptive")
        );
        assert_eq!(
            card["content"]["body"][0]["text"],
            json!("[info] Tenant provisioned")
        );
        assert_eq!(card["content"]["body"][1]["text"], json!("Acme is ready"));
    }

    /// A webhook post carries the notification's facts and is signed under
    /// its id.
    #[test]
    fn a_webhook_post_is_signed_under_the_notification_id() {
        let notification = titled("Tenant provisioned");

        let message = webhook(&notification, &Secret::new("dsec_aw==")).unwrap();

        let body = json_of(&message);
        assert_eq!(body["id"], json!(notification.id().to_string()));
        assert_eq!(body["severity"], json!("info"));
        let signed = message.signed.unwrap();
        assert_eq!(signed.id, notification.id().to_string());
        assert!(signed.signature.starts_with("v1,"));
    }
}
