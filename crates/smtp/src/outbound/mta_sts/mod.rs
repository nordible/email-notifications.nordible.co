/*
 * SPDX-FileCopyrightText: 2026 Nordible Solutions <mail@nordible.co>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod lookup;
pub mod parse;
pub mod verify;

#[derive(Debug)]
pub enum Error {
    Dns(mail_auth::Error),
    Http(reqwest::Error),
    InvalidPolicy(String),
}
