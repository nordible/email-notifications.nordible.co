/*
 * SPDX-FileCopyrightText: 2026 Nordible Solutions <mail@nordible.co>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PlanTier {
    Trial,
    Basic,
    Starter,
    Professional,
}

impl PlanTier {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "basic" => PlanTier::Basic,
            "starter" => PlanTier::Starter,
            "professional" | "pro" => PlanTier::Professional,
            _ => PlanTier::Trial,
        }
    }

    /// Storage quota per mailbox in bytes matching marketing site offerings
    pub fn mailbox_quota_bytes(&self) -> u64 {
        match self {
            PlanTier::Trial => 10 * 1024 * 1024,                  // 10 MB
            PlanTier::Basic => 5 * 1024 * 1024 * 1024,             // 5 GB
            PlanTier::Starter => 10 * 1024 * 1024 * 1024,          // 10 GB
            PlanTier::Professional => 30 * 1024 * 1024 * 1024,     // 30 GB
        }
    }

    /// Default max account limit for the tenant
    pub fn default_max_accounts(&self) -> u64 {
        match self {
            PlanTier::Trial => 1,
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
        // Trial default fallback
        let trial = PlanTier::from_str("unknown");
        assert_eq!(trial, PlanTier::Trial);
        assert_eq!(trial.mailbox_quota_bytes(), 10 * 1024 * 1024); // 10 MB
        assert_eq!(trial.default_max_accounts(), 1);

        // Basic Plan (5 GB)
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
