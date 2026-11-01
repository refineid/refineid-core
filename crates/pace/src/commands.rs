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

//! The two ISO 7816-4 commands the PACE handshake issues.
//!
//! `MSE:Set AT` opens the handshake, carrying the mechanism, password
//! reference, and domain parameter. `GENERAL AUTHENTICATE` runs the four
//! authentication rounds; the first three set the command-chaining
//! class, the last does not. Both carry no credential material, so they
//! are ordinary replay-safe commands.

use refineid_apdu::{ApduClass, CommandApdu, CommandDataError, CommandHeader};

/// `MANAGE SECURITY ENVIRONMENT` instruction.
pub(crate) const MSE_INS: u8 = 0x22;
/// P1 for `MSE:Set` used to configure verification.
pub(crate) const MSE_P1_SET_AT: u8 = 0xC1;
/// P2 selecting the authentication template.
pub(crate) const MSE_P2_AUTH_TEMPLATE: u8 = 0xA4;

/// `GENERAL AUTHENTICATE` instruction.
const GA_INS: u8 = 0x86;
/// P1 for `GENERAL AUTHENTICATE`.
const GA_P1: u8 = 0x00;
/// P2 for `GENERAL AUTHENTICATE`.
const GA_P2: u8 = 0x00;
/// Le requesting every available response byte.
const GA_LE_ANY: u8 = 0x00;

/// `MSE:Set AT`, the PACE opening command. The data field is the
/// pre-assembled BER-TLV mechanism, password-reference, and domain
/// objects.
#[derive(Debug, Clone)]
pub struct MseSetAt {
    /// Pre-assembled BER-TLV data field.
    pub data: Vec<u8>,
}

impl MseSetAt {
    /// Serialise into a case-3 command APDU.
    ///
    /// # Errors
    ///
    /// [`CommandDataError`] when the data field is empty or exceeds the
    /// short-form capacity.
    pub fn into_apdu(self) -> Result<CommandApdu, CommandDataError> {
        CommandApdu::case_3(
            CommandHeader {
                class: ApduClass::Plain,
                instruction: MSE_INS,
                p1: MSE_P1_SET_AT,
                p2: MSE_P2_AUTH_TEMPLATE,
            },
            &self.data,
        )
    }
}

/// `GENERAL AUTHENTICATE`, carrying a step-specific payload wrapped in
/// the dynamic-authentication-data template.
#[derive(Debug, Clone)]
pub struct GeneralAuthenticate {
    /// `true` for the chained rounds, `false` for the final round.
    pub chain: bool,
    /// The dynamic-authentication-data payload.
    pub payload: Vec<u8>,
}

impl GeneralAuthenticate {
    /// Serialise into a case-4 command APDU.
    ///
    /// # Errors
    ///
    /// [`CommandDataError`] when the payload is empty or exceeds the
    /// short-form capacity.
    pub fn into_apdu(self) -> Result<CommandApdu, CommandDataError> {
        let class = if self.chain {
            ApduClass::ChainedFirst
        } else {
            ApduClass::Plain
        };
        CommandApdu::case_4(
            CommandHeader {
                class,
                instruction: GA_INS,
                p1: GA_P1,
                p2: GA_P2,
            },
            &self.payload,
            GA_LE_ANY,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{
        GA_INS, GA_LE_ANY, GA_P1, GA_P2, GeneralAuthenticate, MSE_INS, MSE_P1_SET_AT,
        MSE_P2_AUTH_TEMPLATE, MseSetAt,
    };
    use refineid_apdu::{ApduClass, CommandDataError};

    /// Tag of a synthetic control-reference data object in the MSE data
    /// field: the cryptographic-mechanism reference (BER-TLV tag `80`).
    const MSE_CRDO_TAG: u8 = 0x80;
    /// Its one-byte value length.
    const MSE_CRDO_LEN: u8 = 0x01;
    /// Its synthetic mechanism-reference value; no protocol meaning.
    const MSE_CRDO_VALUE: u8 = 0xAA;
    /// A synthetic MSE data field: one control-reference data object.
    const MSE_DATA: &[u8] = &[MSE_CRDO_TAG, MSE_CRDO_LEN, MSE_CRDO_VALUE];

    /// Tag of the dynamic-authentication-data template that wraps a
    /// GENERAL AUTHENTICATE payload (BER-TLV tag `7C`).
    const GA_TEMPLATE_TAG: u8 = 0x7C;
    /// The template's length byte for an empty body.
    const GA_EMPTY_LEN: u8 = 0x00;
    /// A synthetic GENERAL AUTHENTICATE payload: the empty template.
    const GA_PAYLOAD: &[u8] = &[GA_TEMPLATE_TAG, GA_EMPTY_LEN];

    /// Expected MSE:Set AT wire, assembled from the named header bytes:
    /// header, Lc, then the data field.
    fn expected_mse_wire() -> Vec<u8> {
        let mut wire = vec![
            ApduClass::Plain.as_byte(),
            MSE_INS,
            MSE_P1_SET_AT,
            MSE_P2_AUTH_TEMPLATE,
        ];
        wire.push(u8::try_from(MSE_DATA.len()).expect("fixture data fits the short form"));
        wire.extend_from_slice(MSE_DATA);
        wire
    }

    /// Expected GENERAL AUTHENTICATE wire for `class`: header, Lc, the
    /// payload, then the expected-length byte.
    fn expected_ga_wire(class: ApduClass) -> Vec<u8> {
        let mut wire = vec![class.as_byte(), GA_INS, GA_P1, GA_P2];
        wire.push(u8::try_from(GA_PAYLOAD.len()).expect("fixture payload fits the short form"));
        wire.extend_from_slice(GA_PAYLOAD);
        wire.push(GA_LE_ANY);
        wire
    }

    #[test]
    fn mse_set_at_matches_the_specified_wire() -> Result<(), CommandDataError> {
        let apdu = MseSetAt {
            data: MSE_DATA.to_vec(),
        }
        .into_apdu()?;
        assert_eq!(apdu.as_bytes(), expected_mse_wire().as_slice());
        Ok(())
    }

    #[test]
    fn general_authenticate_chaining_selects_the_class() -> Result<(), CommandDataError> {
        let chained = GeneralAuthenticate {
            chain: true,
            payload: GA_PAYLOAD.to_vec(),
        }
        .into_apdu()?;
        assert_eq!(
            chained.as_bytes(),
            expected_ga_wire(ApduClass::ChainedFirst).as_slice()
        );

        let final_round = GeneralAuthenticate {
            chain: false,
            payload: GA_PAYLOAD.to_vec(),
        }
        .into_apdu()?;
        assert_eq!(
            final_round.as_bytes(),
            expected_ga_wire(ApduClass::Plain).as_slice()
        );
        Ok(())
    }
}
