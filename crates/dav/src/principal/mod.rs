/*
 * SPDX-FileCopyrightText: 2026 Nordible Solutions <mail@nordible.co>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::auth::AccountCache;
use dav_proto::schema::response::Href;
use groupware::RFC_3986;

use crate::DavResourceName;

pub mod matching;
pub mod propfind;
pub mod propsearch;

pub trait CurrentUserPrincipal {
    fn current_user_principal(&self) -> Href;
}

impl CurrentUserPrincipal for AccountCache {
    fn current_user_principal(&self) -> Href {
        Href(format!(
            "{}/{}/",
            DavResourceName::Principal.base_path(),
            percent_encoding::utf8_percent_encode(self.name(), RFC_3986)
        ))
    }
}
