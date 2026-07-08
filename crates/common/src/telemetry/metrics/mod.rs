/*
 * SPDX-FileCopyrightText: 2026 Nordible Solutions <mail@nordible.co>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod otel;
pub mod prometheus;

// SPDX-SnippetBegin
// SPDX-FileCopyrightText: 2026 Nordible Solutions <mail@nordible.co>
// SPDX-License-Identifier: LicenseRef-SEL
#[cfg(feature = "enterprise")]
pub mod store;
// SPDX-SnippetEnd

#[cfg(any(feature = "dev_mode", feature = "test_mode"))]
pub mod test_data;
