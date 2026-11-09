//! A GitHub-style activity calendar for organizations and tenants.
//!
//! This module holds the rules. It picks the days a calendar covers and
//! sorts each event into a category. It fills quiet days with zero and
//! grades each day into a level from light to dark. Reading the raw counts
//! from storage happens in the application and infrastructure layers.

pub mod calendar;
pub mod category;
pub mod range;
pub mod scope;

pub use calendar::{ActivityCalendar, ActivityDay, ActivityLevel, DailyCategoryCount};
pub use category::ActivityCategory;
pub use range::CalendarRange;
pub use scope::ActivityScope;
