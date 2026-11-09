//! The XML the S3 API speaks: the bodies the store is sent for a batch
//! delete and a finished upload, and what is read from its answers.
//!
//! Every key written into a body is escaped, and every answer is read for
//! the few elements the store is asked for, by their local names, so the
//! namespace AWS adds and the one other stores leave out read the same.

use ianua_domain::shared::errors::DomainError;
use roxmltree::{Document, Node};

/// The code a store gives an object that is not there.
pub(super) const NO_SUCH_KEY: &str = "NoSuchKey";

/// The code a store gives an upload that is not there, finished or
/// aborted already.
pub(super) const NO_SUCH_UPLOAD: &str = "NoSuchUpload";

/// The declaration every body sent starts with.
const DECLARATION: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>";

/// One page of a listing: the keys on it, and the token of the next page
/// when one follows.
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct Listed {
    /// The keys on the page.
    pub(super) keys: Vec<String>,
    /// The token that asks for the next page.
    pub(super) next: Option<String>,
}

/// One page of the uploads left unfinished: each key and upload id, and
/// where the next page starts when one follows.
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct Pending {
    /// Each unfinished upload, as its key and its upload id.
    pub(super) uploads: Vec<(String, String)>,
    /// The key and upload id the next page starts after.
    pub(super) next: Option<(String, String)>,
}

/// One part of a multipart upload: its number and the tag the store gave
/// it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Part {
    /// Its number, from 1.
    pub(super) number: usize,
    /// The `ETag` the store answered its upload with, quotes and all.
    pub(super) tag: String,
}

/// The body of a batch delete of `keys`, asking to hear only of failures.
pub(super) fn delete_request(keys: &[String]) -> String {
    let objects: String = keys
        .iter()
        .map(|key| format!("<Object><Key>{}</Key></Object>", xml_text(key)))
        .collect();
    format!("{DECLARATION}<Delete><Quiet>true</Quiet>{objects}</Delete>")
}

/// The body that finishes a multipart upload of `parts`.
pub(super) fn completion(parts: &[Part]) -> String {
    let listed: String = parts
        .iter()
        .map(|part| {
            format!(
                "<Part><PartNumber>{}</PartNumber><ETag>{}</ETag></Part>",
                part.number,
                xml_text(&part.tag)
            )
        })
        .collect();
    format!("{DECLARATION}<CompleteMultipartUpload>{listed}</CompleteMultipartUpload>")
}

/// The upload id a started multipart upload was given.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when the answer is not XML or
/// names none.
pub(super) fn upload_id(xml: &str) -> Result<String, DomainError> {
    let document = parsed(xml)?;
    first_text(document.root(), "UploadId")
        .filter(|id| !id.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| DomainError::infra_msg("the object store started an upload with no id"))
}

/// Refuses the answer to a finished upload when it is a failure: a store
/// may answer `200` and still write an `<Error>`.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when the answer is not XML, or
/// is not the finished upload's result.
pub(super) fn ensure_completed(xml: &str) -> Result<(), DomainError> {
    let document = parsed(xml)?;
    if document
        .root_element()
        .has_tag_name("CompleteMultipartUploadResult")
    {
        return Ok(());
    }
    Err(DomainError::infra_msg(
        "the object store did not finish the upload",
    ))
}

/// One page of a `ListObjectsV2` answer.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when the answer is not XML, or
/// says another page follows without saying how to ask for it.
pub(super) fn listed(xml: &str) -> Result<Listed, DomainError> {
    let document = parsed(xml)?;
    let root = document.root_element();
    let keys = root
        .children()
        .filter(|node| node.has_tag_name("Contents"))
        .filter_map(|contents| child_text(contents, "Key"))
        .map(str::to_owned)
        .collect();
    let truncated = child_text(root, "IsTruncated") == Some("true");
    let next = child_text(root, "NextContinuationToken")
        .filter(|token| !token.is_empty())
        .map(str::to_owned);
    if truncated && next.is_none() {
        return Err(DomainError::infra_msg(
            "the object store cut a listing short without a way to go on",
        ));
    }
    Ok(Listed {
        keys,
        next: next.filter(|_| truncated),
    })
}

/// One page of a `ListMultipartUploads` answer.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when the answer is not XML, or
/// says another page follows without saying where it starts.
pub(super) fn pending(xml: &str) -> Result<Pending, DomainError> {
    let document = parsed(xml)?;
    let root = document.root_element();
    let uploads = root
        .children()
        .filter(|node| node.has_tag_name("Upload"))
        .filter_map(|upload| {
            let key = child_text(upload, "Key")?;
            let id = child_text(upload, "UploadId")?;
            Some((key.to_owned(), id.to_owned()))
        })
        .collect();
    let truncated = child_text(root, "IsTruncated") == Some("true");
    let next = child_text(root, "NextKeyMarker")
        .zip(child_text(root, "NextUploadIdMarker"))
        .filter(|(key, _)| !key.is_empty())
        .map(|(key, id)| (key.to_owned(), id.to_owned()));
    if truncated && next.is_none() {
        return Err(DomainError::infra_msg(
            "the object store cut a listing short without a way to go on",
        ));
    }
    Ok(Pending {
        uploads,
        next: next.filter(|_| truncated),
    })
}

/// The error codes of the objects a batch delete could not remove. An
/// object already gone is not one of them.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when the answer is not XML.
pub(super) fn delete_failures(xml: &str) -> Result<Vec<String>, DomainError> {
    let document = parsed(xml)?;
    let failures = document
        .root_element()
        .children()
        .filter(|node| node.has_tag_name("Error"))
        .map(|error| child_text(error, "Code").unwrap_or_default().to_owned())
        .filter(|code| code != NO_SUCH_KEY)
        .collect();
    Ok(failures)
}

/// The error code of a store's failure, if it names one.
pub(super) fn error_code(xml: &str) -> Option<String> {
    let document = Document::parse(xml).ok()?;
    first_text(document.root(), "Code").map(str::to_owned)
}

/// `text` escaped as XML text.
fn xml_text(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// `xml` parsed.
fn parsed(xml: &str) -> Result<Document<'_>, DomainError> {
    Document::parse(xml).map_err(DomainError::infra)
}

/// The trimmed text of the first element named `name` beneath `node`.
fn first_text<'a>(node: Node<'a, '_>, name: &str) -> Option<&'a str> {
    node.descendants()
        .find(|found| found.has_tag_name(name))
        .and_then(|found| found.text())
        .map(str::trim)
}

/// The trimmed text of the child element named `name` of `node`.
fn child_text<'a>(node: Node<'a, '_>, name: &str) -> Option<&'a str> {
    node.children()
        .find(|found| found.has_tag_name(name))
        .and_then(|found| found.text())
        .map(str::trim)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A page of AWS's listing, its namespace and all, gives its keys and
    /// the token of the next page.
    #[test]
    fn a_listing_page_gives_its_keys_and_the_next_token() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
            <ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
              <Name>acme-files</Name><Prefix>logos/</Prefix><KeyCount>2</KeyCount>
              <IsTruncated>true</IsTruncated>
              <Contents><Key>logos/a/logo</Key><Size>3</Size></Contents>
              <Contents><Key>logos/b/logo</Key><Size>4</Size></Contents>
              <NextContinuationToken>1ueGcxLPRx1Tr</NextContinuationToken>
            </ListBucketResult>"#;

        let page = listed(xml).unwrap();

        assert_eq!(page.keys, vec!["logos/a/logo", "logos/b/logo"]);
        assert_eq!(page.next.as_deref(), Some("1ueGcxLPRx1Tr"));
    }

    /// The last page of a listing names no next page.
    #[test]
    fn the_last_page_names_no_next_one() {
        let xml = "<ListBucketResult><IsTruncated>false</IsTruncated>\
                   <Contents><Key>a</Key></Contents></ListBucketResult>";

        assert_eq!(listed(xml).unwrap().next, None);
    }

    /// A truncated object listing without a continuation token fails parsing.
    #[test]
    fn a_page_cut_short_without_a_token_is_refused() {
        let xml = "<ListBucketResult><IsTruncated>true</IsTruncated></ListBucketResult>";

        assert!(listed(xml).is_err());
    }

    /// The unfinished uploads of a page are read with their ids, and the
    /// markers of the next page.
    #[test]
    fn unfinished_uploads_are_read_with_their_ids() {
        let xml = "<ListMultipartUploadsResult><IsTruncated>true</IsTruncated>\
                   <NextKeyMarker>logos/a/logo</NextKeyMarker>\
                   <NextUploadIdMarker>u2</NextUploadIdMarker>\
                   <Upload><Key>logos/a/logo</Key><UploadId>u2</UploadId></Upload>\
                   </ListMultipartUploadsResult>";

        let page = pending(xml).unwrap();

        assert_eq!(
            page.uploads,
            vec![("logos/a/logo".to_owned(), "u2".to_owned())]
        );
        assert_eq!(
            page.next,
            Some(("logos/a/logo".to_owned(), "u2".to_owned()))
        );
    }

    /// A batch-delete body escapes XML characters in its object key and requests
    /// quiet results.
    #[test]
    fn a_key_is_escaped_in_a_batch() {
        let body = delete_request(&["a&b<c>".to_owned()]);

        assert!(body.contains("<Object><Key>a&amp;b&lt;c&gt;</Key></Object>"));
        assert!(body.contains("<Quiet>true</Quiet>"));
    }

    /// A finished upload lists its parts in order with their tags.
    #[test]
    fn a_completion_lists_each_part_with_its_tag() {
        let parts = [
            Part {
                number: 1,
                tag: "\"a1\"".to_owned(),
            },
            Part {
                number: 2,
                tag: "\"b2\"".to_owned(),
            },
        ];

        let body = completion(&parts);

        assert!(body.contains(
            "<Part><PartNumber>1</PartNumber><ETag>\"a1\"</ETag></Part>\
             <Part><PartNumber>2</PartNumber><ETag>\"b2\"</ETag></Part>"
        ));
    }

    /// An upload completion body containing an error is rejected, while a
    /// completion-result body succeeds.
    #[test]
    fn an_error_answered_with_success_is_a_failure() {
        let failed = "<Error><Code>InternalError</Code></Error>";
        let done = "<CompleteMultipartUploadResult><Key>a</Key></CompleteMultipartUploadResult>";

        assert!(ensure_completed(failed).is_err());
        assert!(ensure_completed(done).is_ok());
    }

    /// A batch delete's failures are read, and an object already gone is
    /// not one.
    #[test]
    fn a_batch_reports_failures_but_not_objects_already_gone() {
        let xml = "<DeleteResult>\
                   <Error><Key>a</Key><Code>AccessDenied</Code></Error>\
                   <Error><Key>b</Key><Code>NoSuchKey</Code></Error>\
                   </DeleteResult>";

        assert_eq!(delete_failures(xml).unwrap(), vec!["AccessDenied"]);
    }

    /// A started upload's id is read, and an answer without one refused.
    #[test]
    fn a_started_upload_gives_its_id() {
        let xml = "<InitiateMultipartUploadResult><Bucket>b</Bucket><Key>k</Key>\
                   <UploadId>VXBsb2FkIElE</UploadId></InitiateMultipartUploadResult>";

        assert_eq!(upload_id(xml).unwrap(), "VXBsb2FkIElE");
        assert!(upload_id("<InitiateMultipartUploadResult/>").is_err());
    }
}
