//! The calls into a customer's AWS account: assuming their role with the
//! platform's own keys, then asking, as that short session, whose account
//! it is, which regions it has, and which database subnet groups.
//!
//! Every call is a query API `POST` to one service in one region, signed
//! with SigV4. The external id and every key travel only in the signed
//! body or headers, never in a URL.

use ianua_domain::domains::organization::cloud::credential::{
    CloudCredential, ExternalId, RoleArn,
};
use ianua_domain::message;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;

use crate::cloud::answers::{MOST_PAGES, another_cloud, reply, too_many_pages};
use crate::cloud::aws::AwsPlatformCredentials;
use crate::cloud::aws::replies::{SignedBy, answered, child_text, first_text, parsed, required};
use crate::cloud::endpoint::CloudEndpoint;
use crate::crypto::sigv4::{
    AccessKey, Payload, Request, Scope, Signing, amz_date, escaped, host_of, sensitive,
};

/// The region STS is asked in: a regional endpoint, whose sessions hold in
/// every region, the ones a customer opted into among them.
const STS_REGION: &str = "us-east-1";

/// How long an assumed session lasts, in seconds: the least AWS allows,
/// since each one serves one check and is dropped.
const SESSION_SECONDS: &str = "900";

/// The encoding signed and sent for every AWS query API call.
const CONTENT_TYPE: &str = "application/x-www-form-urlencoded; charset=utf-8";

/// What the customer is told when AWS will not let us assume the role.
const ASSUME_REFUSAL: &str = "AWS refused to let us assume the role. Check that the role still \
                              exists and that its trust policy names our account and the \
                              external id we gave you.";

/// What the customer is told when the assumed role may not do what we ask.
const SESSION_REFUSAL: &str = "AWS let us assume the role, but it may not read what we need. \
                               Check that its policy allows ec2:DescribeRegions and \
                               rds:DescribeDBSubnetGroups.";

/// What a session is named in the customer's CloudTrail, by its purpose.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Purpose {
    /// Proving the role works.
    Verify,
    /// Listing regions and networks.
    Discover,
}

impl Purpose {
    /// The session's name, as the customer's CloudTrail shows it.
    fn session_name(self) -> &'static str {
        match self {
            Self::Verify => "ianua-verify",
            Self::Discover => "ianua-discovery",
        }
    }
}

/// The short-lived keys an assumed role granted.
pub(crate) struct Session {
    access_key_id: String,
    secret: Secret,
    token: Secret,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Session(<redacted>)")
    }
}

/// One service in one region.
struct Service<'a> {
    name: &'a str,
    region: &'a str,
}

/// The key one call is signed with, its session token among it, and whose
/// key it is.
struct Signer<'a> {
    key: AccessKey<'a>,
    signed_by: SignedBy,
    service: Service<'a>,
}

/// The client every AWS adapter of one factory shares.
pub(crate) struct AwsAccounts {
    pub(crate) http: reqwest::Client,
    pub(crate) platform: AwsPlatformCredentials,
    pub(crate) endpoint: CloudEndpoint,
}

impl AwsAccounts {
    /// The session `credential`'s role grants for `purpose`.
    pub(crate) async fn session(
        &self,
        credential: &CloudCredential,
        purpose: Purpose,
    ) -> Result<Session, DomainError> {
        let CloudCredential::AwsAssumeRole {
            role_arn,
            external_id,
        } = credential
        else {
            return Err(another_cloud("AWS"));
        };
        ensure_in_reach(role_arn)?;
        self.assume(role_arn, external_id, purpose).await
    }

    /// The session `role_arn` grants under `external_id`.
    async fn assume(
        &self,
        role_arn: &RoleArn,
        external_id: &ExternalId,
        purpose: Purpose,
    ) -> Result<Session, DomainError> {
        let form = [
            ("Action", "AssumeRole"),
            ("Version", "2011-06-15"),
            ("RoleArn", role_arn.as_str()),
            ("RoleSessionName", purpose.session_name()),
            ("ExternalId", external_id.as_str()),
            ("DurationSeconds", SESSION_SECONDS),
        ];
        let signer = Signer {
            key: AccessKey {
                id: &self.platform.access_key_id,
                secret: self.platform.secret_access_key.expose(),
                token: self.platform.session_token.as_ref().map(Secret::expose),
            },
            signed_by: SignedBy::Platform,
            service: Service {
                name: "sts",
                region: STS_REGION,
            },
        };
        let xml = self.call(&signer, &form, ASSUME_REFUSAL).await?;
        session_from(&xml)
    }

    /// The account `session` acts in.
    pub(crate) async fn account_of(&self, session: &Session) -> Result<String, DomainError> {
        let form = [("Action", "GetCallerIdentity"), ("Version", "2011-06-15")];
        let sts = Service {
            name: "sts",
            region: STS_REGION,
        };
        let xml = self
            .call(&signer_of(session, sts), &form, ASSUME_REFUSAL)
            .await?;
        required(&xml, "Account")
    }

    /// The region codes enabled in `session`'s account.
    pub(crate) async fn region_codes(&self, session: &Session) -> Result<Vec<String>, DomainError> {
        let form = [
            ("Action", "DescribeRegions"),
            ("Version", "2016-11-15"),
            ("Filter.1.Name", "opt-in-status"),
            ("Filter.1.Value.1", "opt-in-not-required"),
            ("Filter.1.Value.2", "opted-in"),
        ];
        let ec2 = Service {
            name: "ec2",
            region: STS_REGION,
        };
        let xml = self
            .call(&signer_of(session, ec2), &form, SESSION_REFUSAL)
            .await?;
        let document = parsed(&xml)?;
        Ok(document
            .descendants()
            .filter(|node| node.has_tag_name("regionName"))
            .filter_map(|node| node.text())
            .map(|code| code.trim().to_owned())
            .collect())
    }

    /// The database subnet groups of `session`'s account in `region`, page
    /// by page.
    pub(crate) async fn subnet_groups(
        &self,
        session: &Session,
        region: &str,
    ) -> Result<Vec<SubnetGroup>, DomainError> {
        let mut groups = Vec::new();
        let mut marker: Option<String> = None;
        for _ in 0..MOST_PAGES {
            let page = self
                .subnet_groups_on(session, region, marker.as_deref())
                .await?;
            groups.extend(page.groups);
            marker = page.marker;
            if marker.is_none() {
                return Ok(groups);
            }
        }
        Err(too_many_pages("AWS"))
    }

    /// One page of the database subnet groups, after `marker` when a page
    /// came before.
    async fn subnet_groups_on(
        &self,
        session: &Session,
        region: &str,
        marker: Option<&str>,
    ) -> Result<SubnetGroupPage, DomainError> {
        let mut form = vec![
            ("Action", "DescribeDBSubnetGroups"),
            ("Version", "2014-10-31"),
            ("MaxRecords", "100"),
        ];
        if let Some(marker) = marker {
            form.push(("Marker", marker));
        }
        let rds = Service {
            name: "rds",
            region,
        };
        let xml = self
            .call(&signer_of(session, rds), &form, SESSION_REFUSAL)
            .await?;
        let document = parsed(&xml)?;
        let marker = document
            .descendants()
            .find(|node| node.has_tag_name("DescribeDBSubnetGroupsResult"))
            .and_then(|result| child_text(result, "Marker"))
            .filter(|marker| !marker.is_empty())
            .map(str::to_owned);
        let groups = document
            .descendants()
            .filter(|node| node.has_tag_name("DBSubnetGroup"))
            .map(SubnetGroup::read)
            .collect();
        Ok(SubnetGroupPage { groups, marker })
    }

    /// The text of a successful call of `form` to the signer's service.
    async fn call(
        &self,
        signer: &Signer<'_>,
        form: &[(&str, &str)],
        refusal: &str,
    ) -> Result<String, DomainError> {
        let public = format!(
            "https://{}.{}.amazonaws.com",
            signer.service.name, signer.service.region
        );
        let url = self.endpoint.url(&public, &[])?;
        let body = form
            .iter()
            .map(|(name, value)| format!("{}={}", escaped(name), escaped(value)))
            .collect::<Vec<_>>()
            .join("&");
        let request = signed_request(&self.http, &url, signer, body)?;
        answered(reply(request).await?, signer.signed_by, refusal)
    }
}

/// The `POST` of `body` to `url`, signed for the signer's service now.
fn signed_request(
    http: &reqwest::Client,
    url: &url::Url,
    signer: &Signer<'_>,
    body: String,
) -> Result<reqwest::RequestBuilder, DomainError> {
    let now = clock::now();
    let date = amz_date(now);
    let host = host_of(url)?;
    let headers = signed_headers(&host, &date, signer.key.token);
    let signing = Signing {
        key: &signer.key,
        scope: Scope {
            region: signer.service.region,
            service: signer.service.name,
        },
        at: now,
    };
    let header = signing.authorization(&Request {
        method: "POST",
        url,
        headers: &headers,
        payload: Payload::Bytes(body.as_bytes()),
    })?;
    let mut request = http
        .post(url.clone())
        .header("content-type", CONTENT_TYPE)
        .header("x-amz-date", date.as_str())
        .header("authorization", sensitive(&header)?);
    if let Some(token) = signer.key.token {
        request = request.header("x-amz-security-token", sensitive(token)?);
    }
    Ok(request.body(body))
}

/// The canonical query headers, including a session token when the key carries one.
fn signed_headers<'a>(
    host: &'a str,
    date: &'a str,
    token: Option<&'a str>,
) -> Vec<(&'a str, &'a str)> {
    let mut headers = vec![
        ("content-type", CONTENT_TYPE),
        ("host", host),
        ("x-amz-date", date),
    ];
    headers.extend(token.map(|token| ("x-amz-security-token", token)));
    headers
}

/// The signer of calls made as `session` to one regional service.
fn signer_of<'a>(session: &'a Session, service: Service<'a>) -> Signer<'a> {
    Signer {
        key: AccessKey {
            id: &session.access_key_id,
            secret: session.secret.expose(),
            token: Some(session.token.expose()),
        },
        signed_by: SignedBy::Session,
        service,
    }
}

/// The session an `AssumeRole` answer grants.
fn session_from(xml: &str) -> Result<Session, DomainError> {
    Ok(Session {
        access_key_id: required(xml, "AccessKeyId")?,
        secret: Secret::new(required(xml, "SecretAccessKey")?),
        token: Secret::new(required(xml, "SessionToken")?),
    })
}

/// Refuses a role in a partition this deployment's keys cannot reach.
fn ensure_in_reach(role_arn: &RoleArn) -> Result<(), DomainError> {
    if role_arn.as_str().starts_with("arn:aws:") {
        return Ok(());
    }
    Err(DomainError::forbidden(message!(
        "infra-this-role-lives-in-an-aws",
        "this role lives in an AWS partition, such as China or GovCloud, that this \
         deployment cannot reach; use a role in a commercial AWS account"
    )))
}

/// One page of subnet groups, and the marker of the next when one follows.
struct SubnetGroupPage {
    groups: Vec<SubnetGroup>,
    marker: Option<String>,
}

/// A database subnet group, as RDS describes it.
pub(crate) struct SubnetGroup {
    /// Its name, which `create-db-instance` takes.
    pub(crate) name: String,
    /// The customer's description of it.
    pub(crate) description: String,
    /// Network identifier displayed beside the customer's subnet group.
    pub(crate) vpc_id: String,
    /// Its status, `Complete` once usable.
    pub(crate) status: String,
    /// The availability zones of its subnets.
    pub(crate) zones: Vec<String>,
}

impl SubnetGroup {
    /// The group a `DBSubnetGroup` element describes.
    fn read(node: roxmltree::Node<'_, '_>) -> Self {
        let text = |name: &str| child_text(node, name).unwrap_or_default().to_owned();
        let zones = node
            .descendants()
            .filter(|found| found.has_tag_name("SubnetAvailabilityZone"))
            .filter_map(|zone| first_text(zone, "Name"))
            .map(str::to_owned)
            .collect();
        Self {
            name: text("DBSubnetGroupName"),
            description: text("DBSubnetGroupDescription"),
            vpc_id: text("VpcId"),
            status: text("SubnetGroupStatus"),
            zones,
        }
    }

    /// Whether RDS can place a database in it: it is complete and spans at
    /// least two availability zones, as RDS requires.
    pub(crate) fn holds_a_database(&self) -> bool {
        let mut zones: Vec<&str> = self
            .zones
            .iter()
            .map(String::as_str)
            .filter(|zone| !zone.is_empty())
            .collect();
        zones.sort_unstable();
        zones.dedup();
        self.status.eq_ignore_ascii_case("complete") && zones.len() >= 2
    }

    /// The name the customer sees: their description, or the group's name,
    /// with the VPC it is in.
    pub(crate) fn shown_name(&self) -> String {
        let named = match self.description.trim() {
            "" => self.name.as_str(),
            description => description,
        };
        match self.vpc_id.trim() {
            "" => named.to_owned(),
            vpc => format!("{named} ({vpc})"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn group(status: &str, zones: &[&str]) -> SubnetGroup {
        SubnetGroup {
            name: "db-private".to_owned(),
            description: String::new(),
            vpc_id: "vpc-1".to_owned(),
            status: status.to_owned(),
            zones: zones.iter().map(|zone| (*zone).to_owned()).collect(),
        }
    }

    /// A complete subnet group spanning two distinct zones is eligible;
    /// incomplete groups and repeated zones are not.
    #[test]
    fn only_a_complete_group_across_two_zones_holds_a_database() {
        assert!(group("Complete", &["eu-central-1a", "eu-central-1b"]).holds_a_database());
        assert!(!group("Complete", &["eu-central-1a", "eu-central-1a"]).holds_a_database());
        assert!(!group("Incomplete", &["eu-central-1a", "eu-central-1b"]).holds_a_database());
    }

    /// A group without a description is shown by its name and VPC.
    #[test]
    fn a_group_is_shown_with_its_vpc() {
        assert_eq!(group("Complete", &[]).shown_name(), "db-private (vpc-1)");
    }

    /// A GovCloud role is forbidden by the commercial-partition adapter.
    #[test]
    fn a_role_in_another_partition_is_refused() {
        let gov = RoleArn::new("arn:aws-us-gov:iam::123456789012:role/Ianua").unwrap();

        assert!(matches!(
            ensure_in_reach(&gov),
            Err(DomainError::Forbidden(_))
        ));
    }

    /// A session's keys never show in its debug output.
    #[test]
    fn a_session_shows_no_keys() {
        let session = Session {
            access_key_id: "ASIA1".to_owned(),
            secret: Secret::new("session-secret"),
            token: Secret::new("session-token"),
        };

        assert_eq!(format!("{session:?}"), "Session(<redacted>)");
    }
}
