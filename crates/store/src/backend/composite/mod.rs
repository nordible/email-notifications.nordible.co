/*
 * SPDX-FileCopyrightText: 2026 Nordible Solutions <mail@nordible.co>
 *
 * SPDX-License-Identifier: LicenseRef-SEL
 *
 * This file is subject to the Nordible Mail Enterprise License Agreement and
 * is NOT open source software.
 *
 */

#[cfg(any(feature = "postgres", feature = "mysql"))]
pub mod read_replica;
pub mod sharded_blob;
pub mod sharded_lookup;
