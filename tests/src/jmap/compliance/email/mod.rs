/*
 * SPDX-FileCopyrightText: 2026 Nordible Solutions <mail@nordible.co>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::jmap::compliance::CompCtx;

pub mod inspect;
pub mod mutate;
pub mod query;

pub async fn run(ctx: &CompCtx<'_>) {
    println!("[compliance] email");
    inspect::run(ctx).await;
    mutate::run(ctx).await;
    query::run(ctx).await;
}
