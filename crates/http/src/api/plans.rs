/*
 * SPDX-FileCopyrightText: 2026 Nordible Solutions <mail@nordible.co>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use serde::{Deserialize, Serialize};

pub const DEFAULT_MAILBOX_QUOTA_BYTES: u64 = 5 * 1024 * 1024 * 1024; // 5 GB default fallback

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub struct PlanTier(pub String);

impl PlanTier {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn from_str(s: &str) -> Self {
        PlanTier(s.to_lowercase().trim().to_string())
    }

    pub fn default_max_accounts(&self) -> u64 {
        u64::MAX
    }
}
