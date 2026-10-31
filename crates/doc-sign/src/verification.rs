// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
//! Readers for verifying signed documents: the signatures and
//! validation store inside a PDF, the entries of an `ASiC-E` or `BDOC`
//! container, the XML its signature files are written in, and the
//! `XAdES` signatures those files carry.
//!
//! Each reader is the single border for its format: it checks every
//! structural rule its specification states and hands out typed facts.
//! Judging a signature from those facts belongs to the caller.

pub mod asic;
pub mod pdf;
pub mod xades;
pub mod xml;

/// The elements of `items` as an array of the length the caller's
/// pattern names, for tests that destructure a result.
#[cfg(test)]
fn exactly<'a, T, const N: usize>(items: &'a [T], what: &str) -> &'a [T; N] {
    items.try_into().expect(what)
}
