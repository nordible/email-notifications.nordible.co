/*
 * SPDX-FileCopyrightText: 2026 Nordible Solutions <mail@nordible.co>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PlanTier {
    Basic,
    Starter,
    Professional,
}

impl PlanTier {
    pub fn as_str(&self) -> &'static str {
        match self {
            PlanTier::Basic => "basic",
            PlanTier::Starter => "starter",
            PlanTier::Professional => "professional",
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "starter" => PlanTier::Starter,
            "professional" | "pro" => PlanTier::Professional,
            _ => PlanTier::Basic,
        }
    }

    /// Storage quota per mailbox in bytes matching marketing site offerings
    pub fn mailbox_quota_bytes(&self) -> u64 {
        match self {
            PlanTier::Basic => 5 * 1024 * 1024 * 1024,             // 5 GB
            PlanTier::Starter => 10 * 1024 * 1024 * 1024,          // 10 GB
            PlanTier::Professional => 30 * 1024 * 1024 * 1024,     // 30 GB
        }
    }

    /// Default max account limit for the tenant
    pub fn default_max_accounts(&self) -> u64 {
        match self {
            PlanTier::Basic => u64::MAX,
            PlanTier::Starter => u64::MAX,
            PlanTier::Professional => u64::MAX,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plan_tier_parsing_and_quotas() {
        // Basic Plan default fallback
        let basic = PlanTier::from_str("basic");
        assert_eq!(basic, PlanTier::Basic);
        assert_eq!(basic.mailbox_quota_bytes(), 5 * 1024 * 1024 * 1024); // 5 GB

        // Starter Plan (10 GB)
        let starter = PlanTier::from_str("starter");
        assert_eq!(starter, PlanTier::Starter);
        assert_eq!(starter.mailbox_quota_bytes(), 10 * 1024 * 1024 * 1024); // 10 GB

        // Professional Plan (30 GB)
        let pro = PlanTier::from_str("professional");
        assert_eq!(pro, PlanTier::Professional);
        assert_eq!(pro.mailbox_quota_bytes(), 30 * 1024 * 1024 * 1024); // 30 GB
    }
}
