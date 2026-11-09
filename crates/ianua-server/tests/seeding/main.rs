//! The one-off commands that make the first records, run on a whole
//! platform over a test database: the installer, the first operator and
//! the demo seeder.

#![cfg(test)]

mod demo;
mod install;
mod operator;
mod support;
