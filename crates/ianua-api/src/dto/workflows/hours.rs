//! Working hours on the wire: the days by name, the times as `09:00`.

use ianua_domain::domains::workflows::design::working_hours::{
    MINUTES_IN_A_DAY, WorkingHours, WorkingHoursParams,
};
use ianua_domain::message;
use ianua_domain::types::Timezone;
use serde::{Deserialize, Serialize};
use time::Weekday;

use crate::error::ApiError;

/// The hours a team works, such as Monday to Friday, `09:00` to `17:00` in
/// `Europe/Berlin`.
#[derive(Serialize, Deserialize, utoipa::ToSchema)]
pub(crate) struct WorkingHoursBody {
    /// The days worked, such as `monday`.
    pub days: Vec<String>,
    /// When work begins, as `HH:MM`.
    pub opens: String,
    /// When work ends that same day, as `HH:MM`; `24:00` for midnight.
    pub closes: String,
    /// The IANA time zone the clock is read in, such as `Europe/Berlin`.
    pub timezone: String,
}

impl TryFrom<WorkingHoursBody> for WorkingHours {
    type Error = ApiError;

    fn try_from(body: WorkingHoursBody) -> Result<Self, Self::Error> {
        let days = body
            .days
            .iter()
            .map(|day| weekday_named(day))
            .collect::<Result<Vec<_>, _>>()?;
        Self::new(WorkingHoursParams {
            days,
            opens: minutes_of(&body.opens)?,
            closes: minutes_of(&body.closes)?,
            timezone: Timezone::new(body.timezone).map_err(ApiError::validation)?,
        })
        .map_err(ApiError::validation)
    }
}

impl From<&WorkingHours> for WorkingHoursBody {
    fn from(hours: &WorkingHours) -> Self {
        Self {
            days: hours
                .days()
                .iter()
                .map(|day| day.to_string().to_lowercase())
                .collect(),
            opens: clock_of(hours.opens()),
            closes: clock_of(hours.closes()),
            timezone: hours.timezone().as_str().to_owned(),
        }
    }
}

/// The weekday `name` names, such as `monday`.
fn weekday_named(name: &str) -> Result<Weekday, ApiError> {
    let days = [
        Weekday::Monday,
        Weekday::Tuesday,
        Weekday::Wednesday,
        Weekday::Thursday,
        Weekday::Friday,
        Weekday::Saturday,
        Weekday::Sunday,
    ];
    days.into_iter()
        .find(|day| day.to_string().eq_ignore_ascii_case(name))
        .ok_or_else(|| {
            ApiError::validation(message!(
                "api-not-a-day-of-the-week",
                format!("{name} is not a day of the week")
            ))
        })
}

/// The minutes after midnight `clock`, as `HH:MM`, names.
fn minutes_of(clock: &str) -> Result<u16, ApiError> {
    let refused = || {
        ApiError::validation(message!(
            "api-not-a-time-of-day",
            format!("{clock} is not a time of day as HH:MM")
        ))
    };
    let (hours, minutes) = clock.split_once(':').ok_or_else(refused)?;
    let hours: u16 = hours.parse().map_err(|_| refused())?;
    let minutes: u16 = minutes.parse().map_err(|_| refused())?;
    hours
        .checked_mul(60)
        .and_then(|whole| whole.checked_add(minutes))
        .filter(|total| minutes < 60 && *total <= MINUTES_IN_A_DAY)
        .ok_or_else(refused)
}

/// `minutes` after midnight as `HH:MM`.
fn clock_of(minutes: u16) -> String {
    format!("{:02}:{:02}", minutes / 60, minutes % 60)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Hours on `days`, from `opens` to `closes`, in Berlin.
    fn body(days: &[&str], opens: &str, closes: &str) -> WorkingHoursBody {
        WorkingHoursBody {
            days: days.iter().map(|&day| day.to_owned()).collect(),
            opens: opens.to_owned(),
            closes: closes.to_owned(),
            timezone: "Europe/Berlin".to_owned(),
        }
    }

    /// Monday and Friday, 09:00 to 17:30 in Berlin, reads back as written.
    #[test]
    fn working_hours_read_back_as_written() {
        let Ok(hours) = WorkingHours::try_from(body(&["monday", "Friday"], "09:00", "17:30"))
        else {
            panic!("the hours read");
        };

        let back = WorkingHoursBody::from(&hours);

        assert_eq!(back.days, ["monday", "friday"]);
        assert_eq!(
            (back.opens.as_str(), back.closes.as_str()),
            ("09:00", "17:30")
        );
    }

    /// A day that is no weekday, a time past midnight and minutes past 59
    /// are each refused.
    #[test]
    fn hours_that_do_not_read_are_refused() {
        assert!(WorkingHours::try_from(body(&["funday"], "09:00", "17:00")).is_err());
        assert!(WorkingHours::try_from(body(&["monday"], "09:00", "25:00")).is_err());
        assert!(WorkingHours::try_from(body(&["monday"], "09:75", "17:00")).is_err());
    }
}
