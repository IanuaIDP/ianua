//! Values in and out of Postgres: a step's parameters bound to the types
//! the database says its statement takes, and each row read back as named
//! values a workflow holds.
//!
//! A value is never pasted into a statement: it travels apart from it, as
//! a bound parameter of the type the database asked for. A type a step
//! cannot send or read is refused with the cast that would make it one,
//! rather than guessed at.

use ianua_domain::domains::workflows::execution::step::ActionOutcome;
use ianua_integration::answer::failed;
use serde_json::{Map, Number, Value};
use time::format_description::well_known::Rfc3339;
use time::{Date, Month, OffsetDateTime, PrimitiveDateTime, UtcOffset};
use tokio_postgres::Row;
use tokio_postgres::types::{ToSql, Type};

/// A statement's parameters, bound in order.
pub(crate) struct Bound(Vec<Box<dyn ToSql + Sync + Send>>);

impl Bound {
    /// The parameters as the client takes them.
    pub(crate) fn as_params(&self) -> Vec<&(dyn ToSql + Sync)> {
        self.0
            .iter()
            .map(|value| value.as_ref() as &(dyn ToSql + Sync))
            .collect()
    }
}

/// `parameters`, a list of values or nothing, bound to `types`, the types
/// the database says the statement takes.
///
/// # Errors
///
/// A failed outcome when the count differs, or a value does not fit its
/// type.
pub(crate) fn bound(parameters: &Value, types: &[Type]) -> Result<Bound, ActionOutcome> {
    let given: &[Value] = match parameters {
        Value::Null => &[],
        Value::Array(values) => values,
        _ => return Err(failed("the parameters are not a list of values")),
    };
    if given.len() != types.len() {
        return Err(failed(&format!(
            "the statement takes {} values and {} were given",
            types.len(),
            given.len()
        )));
    }
    given
        .iter()
        .zip(types)
        .enumerate()
        .map(|(index, (value, kind))| value_for(value, kind, index + 1))
        .collect::<Result<_, _>>()
        .map(Bound)
}

/// `value` as parameter `position` of type `kind`.
fn value_for(
    value: &Value,
    kind: &Type,
    position: usize,
) -> Result<Box<dyn ToSql + Sync + Send>, ActionOutcome> {
    let misfit = || value_misfit(kind, position);
    let bound: Box<dyn ToSql + Sync + Send> = match *kind {
        Type::BOOL => Box::new(present(value, Value::as_bool).ok_or_else(misfit)?),
        Type::INT2 => Box::new(whole::<i16>(value).ok_or_else(misfit)?),
        Type::INT4 => Box::new(whole::<i32>(value).ok_or_else(misfit)?),
        Type::INT8 => Box::new(whole::<i64>(value).ok_or_else(misfit)?),
        Type::FLOAT4 => Box::new(
            present(value, |number| number.as_f64().map(|number| number as f32))
                .ok_or_else(misfit)?,
        ),
        Type::FLOAT8 => Box::new(present(value, Value::as_f64).ok_or_else(misfit)?),
        Type::TEXT | Type::VARCHAR | Type::BPCHAR | Type::NAME => {
            Box::new(present(value, |text| text.as_str().map(str::to_owned)).ok_or_else(misfit)?)
        }
        Type::JSON | Type::JSONB => {
            Box::new(present(value, |json| Some(json.clone())).ok_or_else(misfit)?)
        }
        Type::UUID => Box::new(
            present(value, |text| uuid::Uuid::parse_str(text.as_str()?).ok()).ok_or_else(misfit)?,
        ),
        Type::TIMESTAMPTZ => Box::new(present(value, moment).ok_or_else(misfit)?),
        Type::TIMESTAMP => Box::new(present(value, utc_timestamp).ok_or_else(misfit)?),
        Type::DATE => Box::new(present(value, day).ok_or_else(misfit)?),
        _ => return Err(unsupported_value(kind, position)),
    };
    Ok(bound)
}

/// Names the parameter whose value does not fit its prepared SQL type.
fn value_misfit(kind: &Type, position: usize) -> ActionOutcome {
    failed(&format!(
        "value ${position} does not fit the {} the statement takes there",
        kind.name()
    ))
}

/// Explains how an unsupported parameter type can be sent with an explicit cast.
fn unsupported_value(kind: &Type, position: usize) -> ActionOutcome {
    failed(&format!(
        "value ${position} is a {} a step cannot send; cast it in the statement, such as ${position}::text::{}",
        kind.name(),
        kind.name()
    ))
}

/// `value` read by `read`, as SQL null for a null: `None` when it is
/// neither null nor readable.
fn present<T>(value: &Value, read: impl FnOnce(&Value) -> Option<T>) -> Option<Option<T>> {
    match value {
        Value::Null => Some(None),
        other => read(other).map(Some),
    }
}

/// `value` as a whole number of type `T`, written whole.
fn whole<T: TryFrom<i64>>(value: &Value) -> Option<Option<T>> {
    present(value, |number| T::try_from(number.as_i64()?).ok())
}

/// `value` as a moment, written as RFC 3339.
fn moment(value: &Value) -> Option<OffsetDateTime> {
    OffsetDateTime::parse(value.as_str()?, &Rfc3339).ok()
}

/// Converts an RFC 3339 moment to the UTC fields stored by a SQL timestamp.
fn utc_timestamp(value: &Value) -> Option<PrimitiveDateTime> {
    let at = moment(value)?.to_offset(UtcOffset::UTC);
    Some(PrimitiveDateTime::new(at.date(), at.time()))
}

/// `value` as a day, written `YYYY-MM-DD`.
fn day(value: &Value) -> Option<Date> {
    let mut parts = value.as_str()?.splitn(3, '-');
    let year = parts.next()?.parse().ok()?;
    let month = Month::try_from(parts.next()?.parse::<u8>().ok()?).ok()?;
    let day = parts.next()?.parse().ok()?;
    Date::from_calendar_date(year, month, day).ok()
}

/// `row`'s columns as named values.
///
/// # Errors
///
/// A failed outcome naming a column of a type a step cannot read, with
/// the cast that would make it one.
pub(crate) fn row_values(row: &Row) -> Result<Map<String, Value>, ActionOutcome> {
    row.columns()
        .iter()
        .enumerate()
        .map(|(index, column)| {
            let value = column_value(row, index, column.type_()).ok_or_else(|| {
                failed(&format!(
                    "the column {} is a {} a step cannot read; cast it, such as {}::text",
                    column.name(),
                    column.type_().name(),
                    column.name()
                ))
            })?;
            Ok((column.name().to_owned(), value))
        })
        .collect()
}

/// Column `index` of `row`, of type `kind`, as a value; `None` for a type
/// a step cannot read.
fn column_value(row: &Row, index: usize, kind: &Type) -> Option<Value> {
    let value = match *kind {
        Type::BOOL => read::<bool>(row, index)?.map(Value::Bool),
        Type::INT2 => read::<i16>(row, index)?.map(Value::from),
        Type::INT4 => read::<i32>(row, index)?.map(Value::from),
        Type::INT8 => read::<i64>(row, index)?.map(Value::from),
        Type::FLOAT4 => read::<f32>(row, index)?.map(|number| fraction(f64::from(number))),
        Type::FLOAT8 => read::<f64>(row, index)?.map(fraction),
        Type::TEXT | Type::VARCHAR | Type::BPCHAR | Type::NAME => {
            read::<String>(row, index)?.map(Value::String)
        }
        Type::JSON | Type::JSONB => read::<Value>(row, index)?,
        Type::UUID => read::<uuid::Uuid>(row, index)?.map(|id| Value::String(id.to_string())),
        Type::TIMESTAMPTZ => read::<OffsetDateTime>(row, index)?.map(|at| {
            at.format(&Rfc3339)
                .map(Value::String)
                .unwrap_or(Value::Null)
        }),
        Type::TIMESTAMP => read::<PrimitiveDateTime>(row, index)?.map(|at| {
            at.assume_utc()
                .format(&Rfc3339)
                .map(Value::String)
                .unwrap_or(Value::Null)
        }),
        Type::DATE => read::<Date>(row, index)?.map(|day| Value::String(day.to_string())),
        _ => return None,
    };
    Some(value.unwrap_or(Value::Null))
}

/// Column `index` of `row` as `T`, `Some(None)` for SQL null, `None` when
/// it does not read as `T`.
fn read<'a, T: tokio_postgres::types::FromSql<'a>>(
    row: &'a Row,
    index: usize,
) -> Option<Option<T>> {
    row.try_get::<_, Option<T>>(index).ok()
}

/// `number` as a value, null when it has no JSON form, as infinity has
/// none.
fn fraction(number: f64) -> Value {
    Number::from_f64(number).map_or(Value::Null, Value::Number)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    /// Pat's values are bound to the types the statement takes: a number
    /// to an integer column, text to text, a moment to a timestamp, and a
    /// null to whatever its column is.
    #[test]
    fn values_are_bound_to_the_statement_s_types() {
        let types = [Type::INT8, Type::TEXT, Type::TIMESTAMPTZ, Type::INT4];
        let values = json!([7, "open", "2026-11-04T08:00:00Z", null]);

        let bound = bound(&values, &types).unwrap();

        assert_eq!(bound.as_params().len(), 4);
    }

    /// Binding fails for too few parameters, text in an integer slot or
    /// an integer outside the requested type's range.
    #[test]
    fn a_misfit_or_missing_value_is_refused() {
        let counted = bound(&json!([1]), &[Type::INT4, Type::INT4]);
        let misfit = bound(&json!(["seven"]), &[Type::INT4]);
        let too_large = bound(&json!([70_000]), &[Type::INT2]);

        assert!(counted.is_err());
        assert!(misfit.is_err());
        assert!(too_large.is_err());
    }

    /// An unsupported numeric parameter is refused with the explicit cast
    /// needed to send its text representation.
    #[test]
    fn an_unsendable_type_names_the_cast() {
        let Err(ActionOutcome::Failed(reason)) = bound(&json!(["12.50"]), &[Type::NUMERIC]) else {
            panic!("a numeric value was bound");
        };

        assert!(
            reason.as_str().contains("$1::text::numeric"),
            "{}",
            reason.as_str()
        );
    }

    /// A day is read from how people write one, and nothing else.
    #[test]
    fn a_day_reads_only_as_year_month_day() {
        assert_eq!(
            day(&json!("2026-11-04")),
            Some(Date::from_calendar_date(2026, Month::November, 4).unwrap())
        );
        assert_eq!(day(&json!("04.11.2026")), None);
        assert_eq!(day(&json!("2026-13-01")), None);
    }
}
