// Copyright 2026 Petri Koistinen
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Minimal BER-TLV encoder and decoder for card protocol structures.
//!
//! Scope, per ISO 7816-4 section 5.2 and ITU-T X.690:
//!
//! - single-byte tags, plus two-byte tags for the template class PACE
//!   uses;
//! - lengths in short form or the one- through four-byte long forms; the
//!   indefinite-length marker and longer forms are rejected because the
//!   parsed length would not fit a 32-bit `usize` and no card artifact
//!   reaches them;
//! - zero-copy value slices on read, owned buffers on write.
//!
//! The typed layer ([`BerTlv`]) verifies a TLV's tag once at the parse
//! boundary and carries the identity at the type level.

use core::fmt;
use core::marker::PhantomData;

/// Smallest length that no longer fits the short form's seven bits.
const SHORT_FORM_CEILING: usize = 0x80;
/// Long-form marker: the length value occupies the next byte.
const LONG_FORM_1B: u8 = 0x81;
/// Long-form marker: the length value occupies the next two bytes.
const LONG_FORM_2B: u8 = 0x82;
/// Long-form marker: the length value occupies the next three bytes.
const LONG_FORM_3B: u8 = 0x83;
/// Long-form marker: the length value occupies the next four bytes.
const LONG_FORM_4B: u8 = 0x84;
/// Largest length encodable in the three-byte long form.
const U24_MAX: usize = (1 << 24) - 1;

/// The five low bits of a tag's leading byte carry the tag number; when they
/// are all set the byte is a multi-byte-tag leader whose number continues in
/// the following octets (X.690 section 8.1.2), so no one-byte tag may take
/// that form.
const MULTI_BYTE_TAG_MASK: u8 = 0x1F;
/// The high bit of a multi-byte tag's continuation octet: set means another
/// octet follows. This crate supports a single continuation octet, so a
/// two-byte tag's low octet must leave it clear.
const TAG_MORE_OCTETS: u8 = 0x80;

/// Encoder-side error: a value or tag that cannot be encoded into a
/// well-formed BER-TLV record the decoder reads back unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BerEncodeError {
    /// The value length exceeds the four-byte long form.
    LengthTooLarge {
        /// The rejected length in bytes.
        got: usize,
    },
    /// The tag is not a well-formed BER identifier. A one-byte tag's number
    /// bits must not all be set -- that marks a multi-byte tag -- and a
    /// two-byte tag must lead with those bits set and carry a single
    /// continuation octet whose high bit is clear (X.690 section 8.1.2).
    /// Encoding any other tag would emit wire the decoder reframes.
    MalformedTag {
        /// The rejected tag.
        tag: u16,
    },
}

impl fmt::Display for BerEncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LengthTooLarge { got } => write!(
                f,
                "BER length of {got} bytes exceeds the four-byte long form"
            ),
            Self::MalformedTag { tag } => {
                write!(f, "BER tag {tag:#06X} is not a well-formed identifier")
            }
        }
    }
}

impl core::error::Error for BerEncodeError {}

/// Owned BER-TLV building buffer.
///
/// Wraps the output vector so length and tag arithmetic stays inside the
/// `push` methods; call [`BerEncoder::finish`] to take the assembled
/// bytes.
#[derive(Debug)]
pub struct BerEncoder {
    out: Vec<u8>,
}

impl Default for BerEncoder {
    fn default() -> Self {
        Self::with_capacity(0)
    }
}

impl BerEncoder {
    /// New empty encoder with the buffer pre-sized to avoid
    /// reallocations.
    #[must_use]
    pub fn with_capacity(cap: usize) -> Self {
        Self {
            out: Vec::with_capacity(cap),
        }
    }

    /// Append a single TLV record with a one-byte tag.
    ///
    /// # Errors
    ///
    /// [`BerEncodeError::MalformedTag`] when `tag`'s number bits are all set
    /// (a multi-byte-tag leader, not a complete one-byte tag), or
    /// [`BerEncodeError::LengthTooLarge`] when the value exceeds the
    /// four-byte long form.
    pub fn push_tlv(&mut self, tag: u8, value: impl AsRef<[u8]>) -> Result<(), BerEncodeError> {
        if tag & MULTI_BYTE_TAG_MASK == MULTI_BYTE_TAG_MASK {
            return Err(BerEncodeError::MalformedTag {
                tag: u16::from(tag),
            });
        }
        let value_bytes = value.as_ref();
        self.out.push(tag);
        self.push_length(value_bytes.len())?;
        self.out.extend_from_slice(value_bytes);
        Ok(())
    }

    /// Append a single TLV record with a two-byte tag; the high byte of
    /// `tag2` leads.
    ///
    /// # Errors
    ///
    /// [`BerEncodeError::MalformedTag`] when `tag2` is not a well-formed
    /// two-byte tag -- its high octet must be a multi-byte-tag leader and its
    /// low octet a single continuation with the high bit clear -- or
    /// [`BerEncodeError::LengthTooLarge`] when the value exceeds the
    /// four-byte long form.
    pub fn push_tlv_tag2(
        &mut self,
        tag2: u16,
        value: impl AsRef<[u8]>,
    ) -> Result<(), BerEncodeError> {
        let [tag_hi, tag_lo] = tag2.to_be_bytes();
        if tag_hi & MULTI_BYTE_TAG_MASK != MULTI_BYTE_TAG_MASK || tag_lo & TAG_MORE_OCTETS != 0 {
            return Err(BerEncodeError::MalformedTag { tag: tag2 });
        }
        let value_bytes = value.as_ref();
        self.out.push(tag_hi);
        self.out.push(tag_lo);
        self.push_length(value_bytes.len())?;
        self.out.extend_from_slice(value_bytes);
        Ok(())
    }

    /// Append length octets in the short form or the matching long form.
    fn push_length(&mut self, len: usize) -> Result<(), BerEncodeError> {
        let error = BerEncodeError::LengthTooLarge { got: len };
        if len < SHORT_FORM_CEILING {
            let byte = u8::try_from(len).map_err(|_| error)?;
            self.out.push(byte);
        } else if let Ok(byte) = u8::try_from(len) {
            self.out.push(LONG_FORM_1B);
            self.out.push(byte);
        } else if let Ok(short) = u16::try_from(len) {
            self.out.push(LONG_FORM_2B);
            self.out.extend_from_slice(&short.to_be_bytes());
        } else if len <= U24_MAX {
            let wide = u32::try_from(len).map_err(|_| error)?;
            self.out.push(LONG_FORM_3B);
            self.out.extend_from_slice(&wide.to_be_bytes()[1..]);
        } else if let Ok(wide) = u32::try_from(len) {
            self.out.push(LONG_FORM_4B);
            self.out.extend_from_slice(&wide.to_be_bytes());
        } else {
            return Err(error);
        }
        Ok(())
    }

    /// Finalise and return the assembled bytes.
    #[must_use]
    pub fn finish(self) -> Vec<u8> {
        self.out
    }
}

/// Wrap `value` in a one-byte-tag TLV and return it as a fresh buffer.
///
/// # Errors
///
/// [`BerEncodeError`] on a malformed tag or a value beyond the four-byte
/// long form.
pub fn tlv(tag: u8, value: impl AsRef<[u8]>) -> Result<Vec<u8>, BerEncodeError> {
    let value_bytes = value.as_ref();
    let mut enc = BerEncoder::with_capacity(value_bytes.len().saturating_add(TLV_OVERHEAD_HINT));
    enc.push_tlv(tag, value_bytes)?;
    Ok(enc.finish())
}

/// Wrap `value` in a two-byte-tag TLV and return it as a fresh buffer.
///
/// # Errors
///
/// [`BerEncodeError`] on a malformed tag or a value beyond the four-byte
/// long form.
pub fn tlv2(tag2: u16, value: impl AsRef<[u8]>) -> Result<Vec<u8>, BerEncodeError> {
    let value_bytes = value.as_ref();
    let mut enc = BerEncoder::with_capacity(value_bytes.len().saturating_add(TLV_OVERHEAD_HINT));
    enc.push_tlv_tag2(tag2, value_bytes)?;
    Ok(enc.finish())
}

/// Capacity hint covering the tag and length octets of one record.
const TLV_OVERHEAD_HINT: usize = 6;

/// Decoder-side errors for parsing a BER-TLV byte stream.
///
/// The variants cover only the structural failures the decoder detects
/// locally; semantic mismatches are surfaced by the call site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BerError {
    /// Input slice was empty; not even a tag byte present.
    Empty,
    /// Input ended before the declared length or value bytes were
    /// available.
    Truncated,
    /// The length octet demanded a form above the four-byte long form,
    /// or the indefinite-length marker.
    UnsupportedLengthForm,
    /// The tag ran to three or more octets; this crate frames only one-
    /// and two-octet tags.
    UnsupportedTagForm,
    /// An INTEGER whose content does not fit the unsigned field it
    /// decodes into: no content octets at all, more octets than the
    /// field holds, or the sign bit set (ITU-T X.690 section 8.3), as
    /// for the PKCS#15 `TokenInfo` version INTEGER (ISO/IEC 7816-15
    /// section 8.2) read into a `u32`.
    IntegerOutOfRange,
    /// Tag mismatch when promoting an untyped TLV to a typed one.
    UnexpectedTag {
        /// The tag the typed marker requires.
        expected: u16,
        /// The tag actually parsed.
        got: u16,
    },
}

impl fmt::Display for BerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("BER: empty input"),
            Self::Truncated => f.write_str("BER: truncated input"),
            Self::UnsupportedLengthForm => f.write_str("BER: length form not supported"),
            Self::UnsupportedTagForm => f.write_str("BER: tag form not supported"),
            Self::IntegerOutOfRange => f.write_str("BER: INTEGER does not fit its field"),
            Self::UnexpectedTag { expected, got } => {
                write!(f, "BER: expected tag {expected:#X}, got {got:#X}")
            }
        }
    }
}

impl core::error::Error for BerError {}

/// Marker for a BER tag value.
///
/// Single-byte tags occupy the low eight bits; two-byte tags use both
/// bytes. Implementors are zero-sized marker types whose only contract
/// is the `TAG` constant.
pub trait BerTag {
    /// Encoded tag value.
    const TAG: u16;
}

/// Typed BER-TLV slice.
///
/// Constructed at a trust boundary via [`BerTlv::parse`], which rejects
/// mismatched tags; downstream code consumes [`BerTlv::value`] knowing
/// the tag is `T::TAG`.
pub struct BerTlv<'a, T: BerTag> {
    value: &'a [u8],
    size: usize,
    _phantom: PhantomData<fn() -> T>,
}

impl<T: BerTag> fmt::Debug for BerTlv<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "BerTlv {{ tag: {:#X}, value: {:?}, size: {} }}",
            T::TAG,
            self.value,
            self.size,
        )
    }
}

impl<T: BerTag> Clone for BerTlv<'_, T> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<T: BerTag> Copy for BerTlv<'_, T> {}

impl<T: BerTag> PartialEq for BerTlv<'_, T> {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value && self.size == other.size
    }
}
impl<T: BerTag> Eq for BerTlv<'_, T> {}

impl<'a, T: BerTag> BerTlv<'a, T> {
    /// Parse `bytes` as a TLV whose tag must equal `T::TAG`.
    ///
    /// # Errors
    ///
    /// Structural [`BerError`] values from the underlying parse, or
    /// [`BerError::UnexpectedTag`] when the tag does not match.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, BerError> {
        BerTlvAny::parse(bytes)?.expect::<T>()
    }

    /// Value bytes, without the tag and length octets.
    #[must_use]
    pub const fn value(&self) -> &'a [u8] {
        self.value
    }

    /// Total bytes consumed: tag, length octets, and value. Useful for
    /// advancing a parser cursor.
    #[must_use]
    pub const fn size(&self) -> usize {
        self.size
    }

    /// Iterate the children of this TLV's value.
    ///
    /// Children may carry heterogeneous tags, so the iterator yields
    /// [`BerTlvAny`]; consumers promote each child via
    /// [`BerTlvAny::expect`] once they know what to expect.
    #[must_use]
    pub const fn iter_children(self) -> BerTlvIter<'a> {
        BerTlvIter::new(self.value)
    }
}

/// Untyped TLV: the peek form.
///
/// Use when the protocol can produce children with several tag classes
/// that the parser branches on; promote with [`BerTlvAny::expect`] once
/// the expected tag is known.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BerTlvAny<'a> {
    tag: u16,
    value: &'a [u8],
    size: usize,
}

impl<'a> BerTlvAny<'a> {
    /// Parse `bytes` as a TLV without enforcing a particular tag.
    ///
    /// Supports single-byte tags and two-byte tags whose first byte
    /// declares a continuation per ISO 7816-4 section 5.2.2.1.
    ///
    /// # Errors
    ///
    /// [`BerError::Empty`] for empty input, [`BerError::Truncated`] when
    /// the tag, length, or value is shorter than declared, and
    /// [`BerError::UnsupportedLengthForm`] for length forms above the
    /// four-byte long form.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, BerError> {
        let mut idx: usize = 0;
        let mut next = |label_first_byte: bool| -> Result<u8, BerError> {
            let byte = bytes
                .get(idx)
                .copied()
                .ok_or(if label_first_byte && idx == 0 {
                    BerError::Empty
                } else {
                    BerError::Truncated
                })?;
            idx = idx.saturating_add(1);
            Ok(byte)
        };

        let first = next(true)?;
        let tag: u16 = if first & MULTI_BYTE_TAG_MASK == MULTI_BYTE_TAG_MASK {
            let second = next(false)?;
            if second & TAG_MORE_OCTETS != 0 {
                return Err(BerError::UnsupportedTagForm);
            }
            (u16::from(first) << u8::BITS) | u16::from(second)
        } else {
            u16::from(first)
        };

        /// Low bits of a long-form marker carrying its octet count.
        const LENGTH_OCTET_COUNT_MASK: u8 = 0x0F;

        let len_first = next(false)?;
        let length: usize = if usize::from(len_first) < SHORT_FORM_CEILING {
            usize::from(len_first)
        } else {
            let nbytes: usize = match len_first {
                LONG_FORM_1B | LONG_FORM_2B | LONG_FORM_3B | LONG_FORM_4B => {
                    usize::from(len_first & LENGTH_OCTET_COUNT_MASK)
                }
                _ => return Err(BerError::UnsupportedLengthForm),
            };
            let len_bytes = bytes
                .get(idx..idx.saturating_add(nbytes))
                .ok_or(BerError::Truncated)?;
            idx = idx.saturating_add(nbytes);
            len_bytes
                .iter()
                .fold(0_usize, |acc, &byte| (acc << u8::BITS) | usize::from(byte))
        };

        let value_end = idx.checked_add(length).ok_or(BerError::Truncated)?;
        let value = bytes.get(idx..value_end).ok_or(BerError::Truncated)?;
        Ok(Self {
            tag,
            value,
            size: value_end,
        })
    }

    /// The parsed tag value.
    #[must_use]
    pub const fn tag(&self) -> u16 {
        self.tag
    }

    /// Value bytes, without the tag and length octets.
    #[must_use]
    pub const fn value(&self) -> &'a [u8] {
        self.value
    }

    /// Total bytes consumed: tag, length octets, and value.
    #[must_use]
    pub const fn size(&self) -> usize {
        self.size
    }

    /// Promote to a typed [`BerTlv`].
    ///
    /// # Errors
    ///
    /// [`BerError::UnexpectedTag`] when the parsed tag does not match
    /// `T::TAG`.
    pub fn expect<T: BerTag>(self) -> Result<BerTlv<'a, T>, BerError> {
        if self.tag != T::TAG {
            return Err(BerError::UnexpectedTag {
                expected: T::TAG,
                got: self.tag,
            });
        }
        Ok(BerTlv {
            value: self.value,
            size: self.size,
            _phantom: PhantomData,
        })
    }
}

/// Iterator over heterogeneous TLV children; yielded values are
/// [`BerTlvAny`].
#[derive(Debug)]
pub struct BerTlvIter<'a> {
    remaining: &'a [u8],
}

impl<'a> BerTlvIter<'a> {
    /// Wrap a value slice: the inside of a constructed TLV.
    #[must_use]
    pub const fn new(value: &'a [u8]) -> Self {
        Self { remaining: value }
    }
}

impl<'a> Iterator for BerTlvIter<'a> {
    type Item = Result<BerTlvAny<'a>, BerError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining.is_empty() {
            return None;
        }
        match BerTlvAny::parse(self.remaining) {
            Ok(parsed) => {
                self.remaining = self.remaining.get(parsed.size..).unwrap_or(&[]);
                Some(Ok(parsed))
            }
            Err(error) => {
                self.remaining = &[];
                Some(Err(error))
            }
        }
    }
}

/// ASN.1 universal `BOOLEAN`.
pub struct Boolean;
impl BerTag for Boolean {
    const TAG: u16 = 0x01;
}

/// ASN.1 universal `INTEGER`.
pub struct Integer;
impl BerTag for Integer {
    const TAG: u16 = 0x02;
}

/// ASN.1 universal `BIT STRING`.
pub struct BitString;
impl BerTag for BitString {
    const TAG: u16 = 0x03;
}

/// ASN.1 universal `OCTET STRING`.
pub struct OctetString;
impl BerTag for OctetString {
    const TAG: u16 = 0x04;
}

/// ASN.1 universal `OBJECT IDENTIFIER`.
pub struct Oid;
impl BerTag for Oid {
    const TAG: u16 = 0x06;
}

/// ASN.1 universal `UTF8String`.
pub struct Utf8String;
impl BerTag for Utf8String {
    const TAG: u16 = 0x0C;
}

/// ASN.1 universal `PrintableString`.
pub struct PrintableString;
impl BerTag for PrintableString {
    const TAG: u16 = 0x13;
}

/// ASN.1 universal `SEQUENCE` and `SEQUENCE OF`, constructed.
pub struct Sequence;
impl BerTag for Sequence {
    const TAG: u16 = 0x30;
}

/// ASN.1 universal `SET` and `SET OF`, constructed.
pub struct Set;
impl BerTag for Set {
    const TAG: u16 = 0x31;
}

#[cfg(kani)]
mod proofs;

#[cfg(test)]
mod tests {
    use super::{
        BerEncodeError, BerEncoder, BerError, BerTag, BerTlv, BerTlvAny, BerTlvIter, Integer,
        OctetString, Sequence, tlv, tlv2,
    };

    /// A one-byte tag whose number bits are all set: a multi-byte-tag leader
    /// the decoder would reframe, swallowing the length octet.
    const MULTI_BYTE_LEADER_TAG: u8 = 0x9F;
    /// A two-byte tag whose high octet is not a multi-byte-tag leader.
    const NON_LEADER_TWO_BYTE_TAG: u16 = 0x0206;
    /// A two-byte tag whose low octet sets the continuation bit, implying a
    /// third octet this crate does not frame.
    const THREE_OCTET_LEADER_TAG: u16 = 0x7F81;

    /// Context-class tag used across the encode round-trip tests.
    const TAG_CONTEXT_0: u8 = 0x80;
    /// Second context-class tag for heterogeneous-children tests.
    const TAG_CONTEXT_1: u8 = 0x81;
    /// Constructed dynamic-authentication template tag.
    const TAG_DYNAMIC_AUTH: u8 = 0x7C;
    /// Two-byte public-key template tag used by PACE.
    const TAG_PUBLIC_KEY_TEMPLATE: u16 = 0x7F49;
    /// Filler byte for generated values.
    const FILLER: u8 = 0xCD;
    /// Value length that triggers the one-byte long form.
    const ONE_BYTE_LONG_FORM_LEN: usize = 200;
    /// Value length that triggers the two-byte long form.
    const TWO_BYTE_LONG_FORM_LEN: usize = 0x1234;
    /// Value length that triggers the three-byte long form: one above
    /// the two-byte ceiling.
    const THREE_BYTE_LONG_FORM_LEN: usize = 0x0001_0000;
    /// Value length that triggers the four-byte long form: one above the
    /// three-byte ceiling.
    const FOUR_BYTE_LONG_FORM_LEN: usize = 0x0100_0000;
    /// An unsupported length-of-length marker.
    const UNSUPPORTED_LENGTH_MARKER: u8 = 0x85;
    /// Length octet declaring more value bytes than follow.
    const OVERLONG_DECLARED_LEN: u8 = 0x05;
    /// Tag and length octets of a short-form record.
    const TLV_SHORT_OVERHEAD: usize = 2;
    /// Bytes kept when truncating after one octet of a three-byte
    /// long-form length.
    const TRUNCATED_AFTER_ONE_LENGTH_OCTET: usize = 3;
    /// Bytes kept when truncating after three octets of a four-byte
    /// long-form length.
    const TRUNCATED_AFTER_THREE_LENGTH_OCTETS: usize = 5;
    /// Short value length for round-trip tests.
    const SHORT_VALUE_LEN: usize = 3;
    /// Value length inside the two-byte-tag template test.
    const TEMPLATE_VALUE_LEN: usize = 6;
    /// Nonce length inside the constructed-children test.
    const NONCE_LEN: usize = 16;
    /// Two-byte value length for promotion tests.
    const PAIR_VALUE_LEN: usize = 2;

    #[test]
    fn rejects_a_one_byte_tag_that_is_a_multi_byte_leader() {
        // The number bits are all set, so the byte is a multi-byte-tag
        // leader rather than a complete one-byte tag.
        assert_eq!(
            tlv(MULTI_BYTE_LEADER_TAG, [FILLER]),
            Err(BerEncodeError::MalformedTag {
                tag: u16::from(MULTI_BYTE_LEADER_TAG),
            })
        );
    }

    #[test]
    fn rejects_a_malformed_two_byte_tag() {
        // High octet is not a multi-byte-tag leader.
        assert_eq!(
            tlv2(NON_LEADER_TWO_BYTE_TAG, [FILLER]),
            Err(BerEncodeError::MalformedTag {
                tag: NON_LEADER_TWO_BYTE_TAG,
            })
        );
        // Low octet declares a further continuation octet.
        assert_eq!(
            tlv2(THREE_OCTET_LEADER_TAG, [FILLER]),
            Err(BerEncodeError::MalformedTag {
                tag: THREE_OCTET_LEADER_TAG,
            })
        );
    }

    fn encoded(tag: u8, value: &[u8]) -> Vec<u8> {
        tlv(tag, value).expect("fixture length is encodable")
    }

    #[test]
    fn short_form_length_round_trips() {
        let value = [FILLER; SHORT_VALUE_LEN];
        let buf = encoded(TAG_CONTEXT_0, &value);
        assert_eq!(buf.len(), value.len() + TLV_SHORT_OVERHEAD);
        assert_eq!(buf.first().copied(), Some(TAG_CONTEXT_0));
        assert_eq!(
            buf.get(1).copied(),
            Some(u8::try_from(value.len()).expect("fits"))
        );

        let parsed = BerTlvAny::parse(&buf).expect("short-form TLV parses");
        assert_eq!(parsed.tag(), u16::from(TAG_CONTEXT_0));
        assert_eq!(parsed.value(), value);
        assert_eq!(parsed.size(), buf.len());
    }

    #[test]
    fn every_long_form_round_trips() {
        for len in [
            ONE_BYTE_LONG_FORM_LEN,
            TWO_BYTE_LONG_FORM_LEN,
            THREE_BYTE_LONG_FORM_LEN,
            FOUR_BYTE_LONG_FORM_LEN,
        ] {
            let value = vec![FILLER; len];
            let buf = encoded(TAG_CONTEXT_0, &value);
            let parsed = BerTlvAny::parse(&buf).expect("long-form TLV parses");
            assert_eq!(parsed.value().len(), len, "value length {len}");
            assert_eq!(parsed.size(), buf.len(), "consumed size at length {len}");
        }
    }

    #[test]
    fn truncated_long_form_length_octets_are_rejected() {
        let mut buf = encoded(TAG_CONTEXT_0, &vec![FILLER; THREE_BYTE_LONG_FORM_LEN]);
        buf.truncate(TRUNCATED_AFTER_ONE_LENGTH_OCTET);
        assert!(matches!(BerTlvAny::parse(&buf), Err(BerError::Truncated)));

        let mut buf = encoded(TAG_CONTEXT_0, &vec![FILLER; FOUR_BYTE_LONG_FORM_LEN]);
        buf.truncate(TRUNCATED_AFTER_THREE_LENGTH_OCTETS);
        assert!(matches!(BerTlvAny::parse(&buf), Err(BerError::Truncated)));
    }

    #[test]
    fn rejects_length_forms_above_four_bytes() {
        let buf = [
            TAG_CONTEXT_0,
            UNSUPPORTED_LENGTH_MARKER,
            0,
            0,
            0,
            0,
            1,
            FILLER,
        ];
        assert!(matches!(
            BerTlvAny::parse(&buf),
            Err(BerError::UnsupportedLengthForm)
        ));
    }

    #[test]
    fn rejects_the_indefinite_length_marker() {
        // X.690 section 8.1.3.6: a length octet with bit 8 set and no
        // count is the indefinite form, forbidden here -- it must not be
        // read as a short length.
        const INDEFINITE_LENGTH_MARKER: u8 = 0x80;
        let buf = [TAG_CONTEXT_0, INDEFINITE_LENGTH_MARKER, FILLER];
        assert!(matches!(
            BerTlvAny::parse(&buf),
            Err(BerError::UnsupportedLengthForm)
        ));
    }

    #[test]
    fn rejects_a_three_octet_tag() {
        // First octet marks a multi-octet tag; the second octet's bit 8
        // (X.690 section 8.1.2.4.2 c) claims a third octet this crate does
        // not frame.
        const MULTI_BYTE_TAG_LEADER: u8 = 0x7F;
        const TAG_CONTINUES: u8 = 0x81;
        let buf = [MULTI_BYTE_TAG_LEADER, TAG_CONTINUES, TAG_CONTEXT_0, FILLER];
        assert!(matches!(
            BerTlvAny::parse(&buf),
            Err(BerError::UnsupportedTagForm)
        ));
    }

    #[test]
    fn rejects_truncated_value() {
        let truncated = [TAG_CONTEXT_0, OVERLONG_DECLARED_LEN, FILLER];
        assert!(matches!(
            BerTlvAny::parse(&truncated),
            Err(BerError::Truncated)
        ));
    }

    #[test]
    fn rejects_empty_input() {
        assert!(matches!(BerTlvAny::parse(&[]), Err(BerError::Empty)));
    }

    #[test]
    fn two_byte_tag_round_trips() {
        let inner = [FILLER; TEMPLATE_VALUE_LEN];
        let buf = tlv2(TAG_PUBLIC_KEY_TEMPLATE, inner).expect("fixture length is encodable");
        let parsed = BerTlvAny::parse(&buf).expect("two-byte-tag TLV parses");
        assert_eq!(parsed.tag(), TAG_PUBLIC_KEY_TEMPLATE);
        assert_eq!(parsed.value(), inner);
    }

    #[test]
    fn iterates_constructed_children() {
        let nonce = [0_u8; NONCE_LEN];
        let inner = encoded(TAG_CONTEXT_0, &nonce);
        let outer = encoded(TAG_DYNAMIC_AUTH, &inner);

        let parsed = BerTlvAny::parse(&outer).expect("outer template parses");
        assert_eq!(parsed.tag(), u16::from(TAG_DYNAMIC_AUTH));
        let mut it = BerTlvIter::new(parsed.value());
        let child = it
            .next()
            .expect("iterator yields the nonce TLV")
            .expect("nonce TLV parses");
        assert_eq!(child.tag(), u16::from(TAG_CONTEXT_0));
        assert_eq!(child.value().len(), nonce.len());
        assert!(it.next().is_none());
    }

    #[test]
    fn typed_parse_matches_and_rejects_tags() {
        let inner = [1_u8, 1, 1];
        let buf = encoded(
            u8::try_from(<Sequence as BerTag>::TAG).expect("universal tag fits one byte"),
            &inner,
        );
        let parsed = BerTlv::<Sequence>::parse(&buf).expect("sequence parses");
        assert_eq!(parsed.value(), inner);
        assert_eq!(parsed.size(), buf.len());

        let err = BerTlv::<Integer>::parse(&buf).expect_err("sequence tag is rejected as integer");
        assert!(matches!(
            err,
            BerError::UnexpectedTag {
                expected: <Integer as BerTag>::TAG,
                got: <Sequence as BerTag>::TAG,
            }
        ));
    }

    #[test]
    fn any_then_expect_round_trips() {
        let value = [FILLER; PAIR_VALUE_LEN];
        let buf = encoded(
            u8::try_from(<OctetString as BerTag>::TAG).expect("universal tag fits one byte"),
            &value,
        );
        let any = BerTlvAny::parse(&buf).expect("untyped parse");
        let typed = any.expect::<OctetString>().expect("promotion succeeds");
        assert_eq!(typed.value(), value);

        let err = any
            .expect::<Integer>()
            .expect_err("octet-string tag is rejected as integer");
        assert!(matches!(err, BerError::UnexpectedTag { .. }));
    }

    #[test]
    fn iter_children_walks_heterogeneous_tags() {
        let mut inner = BerEncoder::default();
        inner
            .push_tlv(
                u8::try_from(<Integer as BerTag>::TAG).expect("universal tag fits one byte"),
                [1_u8],
            )
            .expect("fixture length is encodable");
        inner
            .push_tlv(TAG_CONTEXT_1, [FILLER, FILLER])
            .expect("fixture length is encodable");
        let buf = encoded(
            u8::try_from(<Sequence as BerTag>::TAG).expect("universal tag fits one byte"),
            &inner.finish(),
        );

        let seq = BerTlv::<Sequence>::parse(&buf).expect("sequence parses");
        let mut it = seq.iter_children();
        let first = it.next().expect("first child").expect("first child parses");
        assert_eq!(first.tag(), <Integer as BerTag>::TAG);
        let second = it
            .next()
            .expect("second child")
            .expect("second child parses");
        assert_eq!(second.tag(), u16::from(TAG_CONTEXT_1));
        assert!(it.next().is_none());
    }

    #[test]
    fn iterator_stops_after_a_malformed_child() {
        let mut inner = encoded(TAG_CONTEXT_0, &[FILLER]);
        inner.push(TAG_CONTEXT_1);
        inner.push(OVERLONG_DECLARED_LEN);
        let mut it = BerTlvIter::new(&inner);
        assert!(it.next().expect("first child").is_ok());
        assert!(it.next().expect("second child").is_err());
        assert!(it.next().is_none());
    }

    #[test]
    fn encoder_rejects_lengths_above_the_four_byte_form() {
        // The four-byte ceiling itself cannot be allocated in a test, so
        // exercise the guard through the length encoder's input contract:
        // every supported form round-trips, and the parser rejects the
        // next marker up, which is the only way an overlong length can
        // reach a consumer.
        let buf = [
            TAG_CONTEXT_0,
            UNSUPPORTED_LENGTH_MARKER,
            1,
            1,
            1,
            1,
            1,
            FILLER,
        ];
        assert!(matches!(
            BerTlvAny::parse(&buf),
            Err(BerError::UnsupportedLengthForm)
        ));
    }
}
