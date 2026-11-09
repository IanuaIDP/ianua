//! A tenant's own versions of the platform's emails, one per email and
//! locale, under row-level security.
//!
//! A template has no id of its own: it is known by its slot, the email and
//! the locale, or no locale for every one without a template of its own.
//! The row is given an id when it is first written and keeps it, so a list
//! by email breaks ties by that id, which the page's cursor carries in
//! place of the locale the template itself sorts by.

mod record;
mod words;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::listing::{Page, PageRequest, SortKey, SortOrder};
use ianua_app::ports::TenantScoped;
use ianua_app::ports::branding::{EmailTemplateSortField, EmailTemplateStore};
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::branding::email_template::{
    EmailTemplate, EmailTemplateType, TemplateSlot,
};
use ianua_domain::shared::errors::DomainError;
use sqlx::PgConnection;
use uuid::Uuid;

use self::record::{TemplateColumns, TemplateRecord, slot_columns, type_word};
use crate::postgres::foundation::paging::{Nullable, PageQuery, SortColumns, in_page_order};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The Postgres store of tenants' email templates.
pub struct PgEmailTemplateStore {
    databases: Arc<Databases>,
}

impl PgEmailTemplateStore {
    /// A store keeping templates in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

impl TenantScoped for PgEmailTemplateStore {}

impl SortColumns for EmailTemplateSortField {
    fn column(self) -> &'static str {
        match self {
            Self::TemplateType => "template_type",
        }
    }

    fn nullable(self) -> Nullable {
        Nullable::Never
    }
}

/// The records of the templates of `tenant` that `ids` names, in the order
/// of `ids`.
async fn records_in_order(
    connection: &mut PgConnection,
    tenant: &Uuid,
    ids: &[Uuid],
) -> Result<Vec<TemplateRecord>, sqlx::Error> {
    let records = sqlx::query_file_as!(
        TemplateRecord,
        "queries/email_templates/by_ids.sql",
        tenant,
        ids
    )
    .fetch_all(connection)
    .await?;
    Ok(in_page_order(ids, records, |record| record.id))
}

/// The keys a listed template sorts by: its type's word, then its row's id.
fn listed_keys((id, template): &(Uuid, EmailTemplate)) -> Vec<SortKey> {
    vec![
        SortKey::from(type_word(template.template_type())),
        SortKey::from(id),
    ]
}

#[async_trait]
impl EmailTemplateStore for PgEmailTemplateStore {
    async fn find(
        &self,
        tenant_id: &ScopedTenant,
        slot: &TemplateSlot,
    ) -> Result<Option<EmailTemplate>, DomainError> {
        let (template_type, locale) = slot_columns(slot);
        let record = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    TemplateRecord,
                    "queries/email_templates/in_slot.sql",
                    tenant_id.as_uuid(),
                    template_type,
                    locale
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        record.map(TemplateRecord::into_template).transpose()
    }

    async fn list_for_type(
        &self,
        tenant_id: &ScopedTenant,
        template_type: EmailTemplateType,
    ) -> Result<Vec<EmailTemplate>, DomainError> {
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    TemplateRecord,
                    "queries/email_templates/of_type.sql",
                    tenant_id.as_uuid(),
                    type_word(template_type)
                )
                .fetch_all(connection)
                .await
            },
        )
        .await?;
        records
            .into_iter()
            .map(TemplateRecord::into_template)
            .collect()
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        template: &EmailTemplate,
    ) -> Result<(), DomainError> {
        let columns = TemplateColumns::of(template);
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/email_templates/save.sql",
                    tenant_id.as_uuid(),
                    columns.template_type,
                    columns.locale,
                    columns.subject,
                    columns.body_html,
                    columns.body_text,
                )
                .execute(connection)
                .await
                .map(|_| ())
            },
        )
        .await
    }

    async fn list_all(
        &self,
        tenant_id: &ScopedTenant,
        sort: &SortOrder<EmailTemplateSortField>,
        page: &PageRequest,
    ) -> Result<Page<EmailTemplate>, DomainError> {
        let keyset = page.keyset(sort)?;
        let tenant = *tenant_id.as_uuid();
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                let ids = PageQuery::ids("id", "email_templates")
                    .filter("tenant_id = ?", tenant)
                    .fetch(&keyset, &mut *connection)
                    .await?;
                records_in_order(connection, &tenant, &ids).await
            },
        )
        .await?;
        let listed = records
            .into_iter()
            .map(TemplateRecord::into_listed)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(keyset
            .seal_by(listed, listed_keys)
            .map(|(_, template)| template))
    }

    async fn delete(
        &self,
        tenant_id: &ScopedTenant,
        slot: &TemplateSlot,
    ) -> Result<(), DomainError> {
        let (template_type, locale) = slot_columns(slot);
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/email_templates/delete.sql",
                    tenant_id.as_uuid(),
                    template_type,
                    locale
                )
                .execute(connection)
                .await
                .map(|_| ())
            },
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::listing::{Limit, Sort};
    use ianua_domain::domains::branding::email_template::{EmailTemplateRow, TemplateLocale};
    use ianua_domain::types::{Preference, TenantId};

    use super::*;
    use crate::test_support::TestDb;
    use crate::test_support::rows::branding::{email_template_row, html_body, locale};

    /// A fresh database, the store on it, and one tenant.
    async fn fixture() -> (TestDb, PgEmailTemplateStore, ScopedTenant) {
        let db = TestDb::fresh().await;
        let store = PgEmailTemplateStore::new(Arc::clone(&db.databases));
        (db, store, ScopedTenant::for_background(TenantId::new()))
    }

    fn template(row: EmailTemplateRow) -> EmailTemplate {
        EmailTemplate::reconstitute(row).unwrap()
    }

    fn slot(template_type: EmailTemplateType, locale: TemplateLocale) -> TemplateSlot {
        TemplateSlot {
            template_type,
            locale,
        }
    }

    /// Saves the fixture template for one tenant's email and locale slot.
    async fn save_slot(store: &PgEmailTemplateStore, tenant: &ScopedTenant, slot: TemplateSlot) {
        store
            .save(
                tenant,
                &template(email_template_row(slot.template_type, slot.locale)),
            )
            .await
            .unwrap();
    }

    /// A saved template is found in its slot, and a template for every
    /// locale apart from one for German.
    #[tokio::test]
    async fn a_saved_template_is_found_in_its_slot() {
        let (_db, store, acme) = fixture().await;
        let german = template(email_template_row(
            EmailTemplateType::Welcome,
            locale("de-DE"),
        ));
        let every = template(email_template_row(
            EmailTemplateType::Welcome,
            TemplateLocale::Fallback,
        ));
        store.save(&acme, &german).await.unwrap();
        store.save(&acme, &every).await.unwrap();

        let found = store
            .find(&acme, &slot(EmailTemplateType::Welcome, locale("de-DE")))
            .await
            .unwrap()
            .unwrap();
        let fallback = store
            .find(&acme, &EmailTemplateType::Welcome.into())
            .await
            .unwrap()
            .unwrap();

        assert_eq!(found.locale(), german.locale());
        assert_eq!(found.subject(), german.subject());
        assert_eq!(found.body_text(), german.body_text());
        assert_eq!(found.body_html(), &Preference::Inherited);
        assert_eq!(fallback.locale(), &TemplateLocale::Fallback);
    }

    /// An empty slot, or another tenant's, finds nothing.
    #[tokio::test]
    async fn a_template_is_found_only_by_its_tenant() {
        let (_db, store, acme) = fixture().await;
        store
            .save(
                &acme,
                &template(email_template_row(
                    EmailTemplateType::Welcome,
                    locale("fr-FR"),
                )),
            )
            .await
            .unwrap();
        let other = ScopedTenant::for_background(TenantId::new());
        let french = slot(EmailTemplateType::Welcome, locale("fr-FR"));

        assert!(store.find(&other, &french).await.unwrap().is_none());
        assert!(
            store
                .find(&acme, &EmailTemplateType::Welcome.into())
                .await
                .unwrap()
                .is_none()
        );
    }

    /// Saving into a slot again replaces the template there, and every
    /// template of one email is listed whatever its locale.
    #[tokio::test]
    async fn saving_again_replaces_the_template_in_its_slot() {
        let (_db, store, acme) = fixture().await;
        save_slot(
            &store,
            &acme,
            slot(EmailTemplateType::Welcome, locale("de-DE")),
        )
        .await;
        save_slot(
            &store,
            &acme,
            slot(EmailTemplateType::Invitation, locale("de-DE")),
        )
        .await;
        let replaced = template(EmailTemplateRow {
            body_html: Preference::Own(html_body()),
            ..email_template_row(EmailTemplateType::Welcome, locale("de-DE"))
        });

        store.save(&acme, &replaced).await.unwrap();
        save_slot(&store, &acme, EmailTemplateType::Welcome.into()).await;

        let welcomes = store
            .list_for_type(&acme, EmailTemplateType::Welcome)
            .await
            .unwrap();
        assert_eq!(welcomes.len(), 2);
        let german = welcomes
            .iter()
            .find(|kept| *kept.locale() == locale("de-DE"))
            .unwrap();
        assert_eq!(german.body_html(), replaced.body_html());
    }

    /// A deleted template is gone from its slot, and the others stay.
    #[tokio::test]
    async fn a_deleted_template_leaves_its_slot_empty() {
        let (_db, store, acme) = fixture().await;
        save_slot(&store, &acme, EmailTemplateType::Welcome.into()).await;
        save_slot(
            &store,
            &acme,
            slot(EmailTemplateType::Welcome, locale("de-DE")),
        )
        .await;

        store
            .delete(&acme, &EmailTemplateType::Welcome.into())
            .await
            .unwrap();

        let left = store
            .list_for_type(&acme, EmailTemplateType::Welcome)
            .await
            .unwrap();
        assert_eq!(left.len(), 1);
        assert_eq!(*left[0].locale(), locale("de-DE"));
    }

    /// The tenant's templates list by email, page by page, templates of one
    /// email across a page boundary included once each.
    #[tokio::test]
    async fn templates_are_listed_page_by_page_by_email() {
        let (_db, store, acme) = fixture().await;
        for (template_type, tag) in [
            (EmailTemplateType::Welcome, "de-DE"),
            (EmailTemplateType::Invitation, "de-DE"),
            (EmailTemplateType::Welcome, "fr-FR"),
        ] {
            save_slot(&store, &acme, slot(template_type, locale(tag))).await;
        }
        let order = SortOrder::single(Sort::ascending(EmailTemplateSortField::TemplateType));

        let page_one = store
            .list_all(&acme, &order, &PageRequest::first(Limit::new(2).unwrap()))
            .await
            .unwrap();
        let after = PageRequest::new(page_one.next.clone(), Limit::new(2).unwrap());
        let page_two = store.list_all(&acme, &order, &after).await.unwrap();

        let types = template_types(&page_one, &page_two);
        assert_eq!(
            types,
            [
                EmailTemplateType::Invitation,
                EmailTemplateType::Welcome,
                EmailTemplateType::Welcome
            ]
        );
        assert_eq!(page_two.items.len(), 1);
        assert!(!page_two.has_next());
    }

    /// Combines template types in the exact order returned by two consecutive pages.
    fn template_types(
        first: &Page<EmailTemplate>,
        second: &Page<EmailTemplate>,
    ) -> Vec<EmailTemplateType> {
        first
            .items
            .iter()
            .chain(&second.items)
            .map(EmailTemplate::template_type)
            .collect()
    }

    /// Reading a stored template containing a loop directive reports
    /// corrupt storage instead of returning the template.
    #[tokio::test]
    async fn a_row_that_breaks_a_rule_of_the_template_is_refused() {
        let (db, store, acme) = fixture().await;
        store
            .save(
                &acme,
                &template(email_template_row(
                    EmailTemplateType::Welcome,
                    TemplateLocale::Fallback,
                )),
            )
            .await
            .unwrap();
        db.tamper("UPDATE email_templates SET body_text = '{% for x in y %}'")
            .await;

        let read = store.find(&acme, &EmailTemplateType::Welcome.into()).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
