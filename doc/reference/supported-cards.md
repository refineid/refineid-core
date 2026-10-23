# FINEID certificate cards

The FINEID certificate cards DVV (formerly VRK) has issued, by
manufacturer and platform version, with the FINEID specification each
implements and the answer-to-reset (ATR, contact) and answer-to-select
(ATS, contactless) each presents. Bytes are hexadecimal, most significant
first.

Source: DVV,
[Technology note -- ATR bytes](https://dvv.fi/documents/16079645/17324992/Technology+note+-+ATR+bytes.pdf)
(v1.0, 2024-08-12).

These crates are generation-agnostic: they read and drive a card through
the same commands, using the per-generation fallback variants the read and
select paths carry, rather than switching on the ATR. The modern citizen
platforms (Thales and Gemalto MultiApp) and the organizational Cosmo /
IAS-ECC platforms are what the code targets; the SetCOS and Segenmark
legacy cards are a different card operating system and are listed for
completeness, not targeted. Observed hardware coverage is in the
[core migration policy](../architecture/core-migration.md).

## Citizen eID cards

| Card | FINEID spec | In production |
| --- | --- | --- |
| Thales MultiApp v5.0 | S4-1 v4.0 | 2023-03-13 → |
| Gemalto MultiApp v4.2 | S4-1 v3.1 | 2021-01-11 – 2023-03-12 |
| Gemalto MultiApp v3.0 | S4-1 v3.0 | 2017-01-01 – 2021-01-10 |
| Setec SetCOS 5.1.X | — | Legacy product |

**Thales MultiApp v5.0**

- ATR: `3B 7F 96 00 00 80 31 B8 65 B0 85 05 00 11 12 24 60 82 90 00`
- ATS: `14 78 77 95 02 80 31 B8 65 B0 85 05 00 11 12 24 60 82 90 00`

**Gemalto MultiApp v4.2**

- ATR: `3B 7F 96 00 00 80 31 B8 65 B0 85 04 02 1B 12 00 F6 82 90 00`
- ATS: `14 78 77 95 02 80 31 B8 65 B0 85 04 02 1B 12 00 F6 82 90 00`

**Gemalto MultiApp v3.0**

- ATR: `3B 7F 96 00 00 80 31 B8 65 B0 85 03 00 EF 12 00 F6 82 90 00`
- ATS: `14 78 77 95 02 80 31 B8 65 B0 85 03 00 EF 12 00 F6 82 90 00`

**Setec SetCOS 5.1.X**

- ATR: `3B 7B 00 00 00 80 62 00 51 56 46 69 6E 45 49 44`
- ATS: not applicable

## Social welfare and organizational cards

| Card | FINEID spec | In production |
| --- | --- | --- |
| Idemia Cosmo X | S1 v5.0 | ~2025 → |
| Idemia ID.me IDeal Citiz 2.17-i | S1 v4.0 | 2019-12-17 → |
| Oberthur Cosmo v7 IAS-ECC | — | ~2010 – 2019-12-16 |

**Idemia Cosmo X**

- ATR: `3B DD 96 00 80 31 FE 45 00 31 B8 64 04 29 EC C1 73 94 01 80 83 49`
- ATS: `3B 89 80 01 00 31 B8 64 04 29 EC C1 73 94 01 80 83`

**Idemia ID.me IDeal Citiz 2.17-i**

- ATR: `3B DD 96 00 80 31 FE 45 00 31 B8 64 04 29 EC C1 73 94 01 80 82 48`
- ATS: `3B 89 80 01 80 57 43 49 54 49 5A 32 31 91`

**Oberthur Cosmo v7 IAS-ECC**

- ATR: `3B DF 96 00 80 31 FE 45 00 31 B8 64 04 29 EC C1 73 94 01 80 82 90 00 00`
- ATS: not applicable

## Health care and organizational cards

| Card | FINEID spec | In production |
| --- | --- | --- |
| Segenmark FINEID | — | Legacy product |

**Segenmark FINEID**

- ATR: `3B 7B 18 00 00 80 62 01 54 56 46 69 6E 45 49 44`
- ATS: not applicable
