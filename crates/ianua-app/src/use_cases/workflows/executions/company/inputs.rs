//! Reading a company step's inputs from its call: texts, ids, numbers and
//! lists of texts, each refused in plain words when it does not read.

use ianua_domain::domains::workflows::data::{FieldName, FlowData, FlowValue};
use ianua_domain::domains::workflows::execution::ActionCall;
use ianua_domain::domains::workflows::execution::step::ActionOutcome;
use uuid::Uuid;

use crate::use_cases::workflows::executions::answers::failed;

/// The most texts a list input names, such as a review's reviewers.
const MOST_LISTED: usize = 50;

/// How far back a reading step looks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Since {
    /// The last hour.
    Hour,
    /// The last day.
    Day,
    /// The last week.
    Week,
    /// The last thirty days.
    Month,
}

impl Since {
    /// How long ago it starts.
    pub(super) fn span(self) -> time::Duration {
        match self {
            Self::Hour => time::Duration::HOUR,
            Self::Day => time::Duration::DAY,
            Self::Week => time::Duration::WEEK,
            Self::Month => time::Duration::days(30),
        }
    }
}

/// The value `call` was given for `input`, if any.
fn given<'a>(call: &'a ActionCall, input: &str) -> Option<&'a FlowData> {
    let name = FieldName::new(input).ok()?;
    call.arguments.field(&name)
}

/// The value `call` was given for `input`, of any kind.
pub(super) fn value<'a>(call: &'a ActionCall, input: &str) -> Result<&'a FlowData, ActionOutcome> {
    given(call, input).ok_or_else(|| failed(&format!("the step's {input} is missing")))
}

/// The text `call` was given for `input`.
pub(super) fn text<'a>(call: &'a ActionCall, input: &str) -> Result<&'a str, ActionOutcome> {
    optional_text(call, input)?.ok_or_else(|| failed(&format!("the step's {input} is missing")))
}

/// The text `call` was given for `input`, when it was given one.
pub(super) fn optional_text<'a>(
    call: &'a ActionCall,
    input: &str,
) -> Result<Option<&'a str>, ActionOutcome> {
    match given(call, input).map(FlowData::value) {
        None | Some(FlowValue::Null) => Ok(None),
        Some(FlowValue::Text(text)) if !text.trim().is_empty() => Ok(Some(text.trim())),
        Some(_) => Err(failed(&format!("the step's {input} is not text"))),
    }
}

/// The id `call` names in `input`.
pub(super) fn id<T>(
    call: &ActionCall,
    input: &str,
    from_uuid: fn(Uuid) -> T,
) -> Result<T, ActionOutcome> {
    let text = text(call, input)?;
    Uuid::parse_str(text)
        .map(from_uuid)
        .map_err(|_| failed(&format!("the step's {input} is not an id")))
}

/// The whole number `call` was given for `input`, from `least` to `most`.
pub(super) fn whole_number(
    call: &ActionCall,
    input: &str,
    least: u32,
    most: u32,
) -> Result<u32, ActionOutcome> {
    let out_of_range = || failed(&format!("the step's {input} is not from {least} to {most}"));
    let number = match given(call, input).map(FlowData::value) {
        Some(FlowValue::Number(number)) => number,
        Some(FlowValue::Text(text)) => text.trim().parse::<f64>().map_err(|_| out_of_range())?,
        _ => return Err(out_of_range()),
    };
    (least..=most)
        .find(|whole| (f64::from(*whole) - number).abs() < f64::EPSILON)
        .ok_or_else(out_of_range)
}

/// The texts `call` was given for `input`: a list of texts, or one text
/// with names separated by commas.
pub(super) fn texts<'a>(call: &'a ActionCall, input: &str) -> Result<Vec<&'a str>, ActionOutcome> {
    let listed: Vec<&str> = match given(call, input).map(FlowData::value) {
        Some(FlowValue::Text(text)) => text.split(',').map(str::trim).collect(),
        Some(FlowValue::List(items)) => items
            .iter()
            .map(|item| match item.value() {
                FlowValue::Text(text) => Ok(text.trim()),
                _ => Err(failed(&format!(
                    "the step's {input} holds something not text"
                ))),
            })
            .collect::<Result<_, _>>()?,
        _ => return Err(failed(&format!("the step's {input} is missing"))),
    };
    let named: Vec<&str> = listed.into_iter().filter(|text| !text.is_empty()).collect();
    if named.is_empty() || named.len() > MOST_LISTED {
        return Err(failed(&format!(
            "the step's {input} names from 1 to {MOST_LISTED}"
        )));
    }
    Ok(named)
}

/// How far back `call` asks to look in `input`, a day when it does not say.
pub(super) fn since(call: &ActionCall, input: &str) -> Result<Since, ActionOutcome> {
    match optional_text(call, input)? {
        None | Some("day") => Ok(Since::Day),
        Some("hour") => Ok(Since::Hour),
        Some("week") => Ok(Since::Week),
        Some("month") => Ok(Since::Month),
        Some(_) => Err(failed(&format!(
            "the step's {input} is not hour, day, week or month"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::data_classification::level::DataClassLevel;
    use ianua_domain::domains::workflows::integration::{
        ActionAccount, IntegrationKey, OperationKey,
    };
    use ianua_domain::shared::events::chain::EventOrigin;
    use ianua_domain::types::{ActionCallId, DeclaredAction, GroupId};

    use super::*;

    /// A company call given `fields`.
    fn call(fields: Vec<(&str, FlowData)>) -> ActionCall {
        let entries = fields
            .into_iter()
            .map(|(name, value)| (FieldName::new(name).unwrap(), value))
            .collect();
        ActionCall {
            call_id: ActionCallId::new(),
            integration: IntegrationKey::new("ianua").unwrap(),
            operation: OperationKey::new("sign-out").unwrap(),
            account: ActionAccount::NoAccount,
            arguments: FlowData::map(entries).unwrap(),
            effect: DeclaredAction::Undeclared,
            exposure: DataClassLevel::Internal,
            origin: EventOrigin::Outside,
        }
    }

    fn text_of(value: &str) -> FlowData {
        FlowData::text(value).unwrap()
    }

    /// A person named by an address reads back trimmed.
    #[test]
    fn a_text_reads_back_trimmed() {
        let call = call(vec![("person", text_of("  lee@acme.test "))]);

        assert_eq!(text(&call, "person").unwrap(), "lee@acme.test");
    }

    /// Missing and blank person fields both produce a failed action outcome
    /// when read as required text.
    #[test]
    fn a_missing_or_blank_text_fails() {
        let blank = call(vec![("person", text_of("   "))]);
        let missing = call(Vec::new());

        assert!(matches!(
            text(&blank, "person"),
            Err(ActionOutcome::Failed(_))
        ));
        assert!(matches!(
            text(&missing, "person"),
            Err(ActionOutcome::Failed(_))
        ));
    }

    /// Reading a group name as an ID fails, while a valid group ID is preserved.
    #[test]
    fn an_id_that_is_not_one_fails() {
        let named = call(vec![("group", text_of("Support"))]);
        let group = GroupId::new();
        let by_id = call(vec![("group", text_of(&group.to_string()))]);

        assert!(id(&named, "group", GroupId::from_uuid).is_err());
        assert_eq!(id(&by_id, "group", GroupId::from_uuid).unwrap(), group);
    }

    /// Hours read as a number or as text, whole and within range; anything
    /// else fails.
    #[test]
    fn hours_are_a_whole_number_within_range() {
        let hours = |value: FlowData| whole_number(&call(vec![("hours", value)]), "hours", 1, 720);

        assert_eq!(hours(FlowData::number(8.0).unwrap()).unwrap(), 8);
        assert_eq!(hours(text_of("24")).unwrap(), 24);
        assert!(hours(FlowData::number(0.0).unwrap()).is_err());
        assert!(hours(FlowData::number(1.5).unwrap()).is_err());
        assert!(hours(FlowData::number(721.0).unwrap()).is_err());
    }

    /// Reviewers come as a list or as text separated by commas, blanks
    /// left out.
    #[test]
    fn reviewers_read_from_a_list_or_commas() {
        let listed = call(vec![(
            "reviewers",
            FlowData::list(vec![text_of("ann@acme.test"), text_of("bob@acme.test")]).unwrap(),
        )]);
        let commas = call(vec![(
            "reviewers",
            text_of("ann@acme.test, ,bob@acme.test"),
        )]);

        assert_eq!(
            texts(&listed, "reviewers").unwrap(),
            ["ann@acme.test", "bob@acme.test"]
        );
        assert_eq!(
            texts(&commas, "reviewers").unwrap(),
            ["ann@acme.test", "bob@acme.test"]
        );
    }

    /// Empty reviewer text and a list exceeding the reviewer limit are rejected.
    #[test]
    fn too_few_or_too_many_reviewers_fail() {
        let none = call(vec![("reviewers", text_of(" , "))]);
        let crowd = vec!["a@acme.test"; MOST_LISTED + 1].join(",");
        let too_many = call(vec![("reviewers", text_of(&crowd))]);

        assert!(texts(&none, "reviewers").is_err());
        assert!(texts(&too_many, "reviewers").is_err());
    }

    /// How far back a step looks is a day when it does not say, and one of
    /// four spans when it does.
    #[test]
    fn since_is_a_day_unless_named() {
        let named = |value: &str| since(&call(vec![("since", text_of(value))]), "since");

        assert_eq!(since(&call(Vec::new()), "since").unwrap(), Since::Day);
        assert_eq!(named("week").unwrap(), Since::Week);
        assert!(named("year").is_err());
    }
}
