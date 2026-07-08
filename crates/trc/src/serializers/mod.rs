/*
 * SPDX-FileCopyrightText: 2026 Nordible Solutions <mail@nordible.co>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod json;
pub mod text;

// SPDX-SnippetBegin
// SPDX-FileCopyrightText: 2026 Nordible Solutions <mail@nordible.co>
// SPDX-License-Identifier: LicenseRef-SEL
#[cfg(feature = "enterprise")]
pub mod binary;
// SPDX-SnippetEnd
