//! Making the tenant look and write like the company: its colour, logo and
//! mail sender, its own words for the platform's emails, checked in the
//! mail that people actually receive and on the sign-in pages they
//! actually see, in the language they read.
//!
//! - `look`: Tess saves a colour and a sender name, recorded once; a
//!   colour that is not one is refused; nobody without the right changes
//!   the look.
//! - `emails`: Tess previews, saves and test-sends her own welcome, Pat
//!   receives it, and a reset brings the platform's words back; a link
//!   hidden in markup is refused; nobody without the right rewrites it.
//! - `logo`: Tess's logo is served from its own address, nothing about it
//!   is taken on trust, and nobody without the right changes it.
//! - `pages`: the sign-in page wears the tenant's logo, colours and
//!   cleaned CSS, in the language the browser asks for.
//! - `languages`: Pat's mail comes in the language she chose.

#![cfg(test)]

mod emails;
mod languages;
mod logo;
mod look;
mod pages;
mod support;
