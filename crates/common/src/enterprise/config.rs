/*
 * SPDX-FileCopyrightText: 2026 Nordible Solutions <mail@nordible.co>
 *
 * SPDX-License-Identifier: LicenseRef-SEL
 *
 * This file is subject to the Nordible Mail Enterprise License Agreement and
 * is NOT open source software.
 *
 */

use super::{
    AlertContent, AlertContentToken, AlertMethod, Enterprise, MetricAlert, SpamFilterLlmConfig,
    license::LicenseKey, llm::AiApiConfig,
};
use crate::{enterprise::llm::ApiType, expr::if_block::BootstrapExprExt};
use ahash::AHashMap;
use registry::schema::{
    enums::AiModelType,
    prelude::{ObjectType, Property},
    structs::{
        self, AiModel, Alert, CalendarAlarm, CalendarScheduling, DataRetention, SecretKeyOptional,
        SecretKeyValue, SpamLlm, SystemSettings,
    },
};
use std::sync::Arc;
use store::{
    registry::{RegistryQuery, bootstrap::Bootstrap, write::RegistryWrite},
    roaring::RoaringBitmap,
};
use trc::MetricType;
use utils::template::Template;

impl Enterprise {
    pub async fn parse(bp: &mut Bootstrap) -> Option<Self> {
        let server_hostname = bp
            .setting_infallible::<SystemSettings>()
            .await
            .default_hostname;
        let license = LicenseKey {
            valid_to: store::write::now() + (86400 * 365 * 10), // 10 years
            valid_from: store::write::now() - 3600,
            domain: server_hostname.to_string(),
            accounts: u32::MAX,
        };
        let logo_url = None;

        let dr = bp.setting_infallible::<DataRetention>().await;

        // Parse AI APIs
        let mut ai_apis = AHashMap::new();
        let mut ai_apis_ids = AHashMap::new();
        for api in bp.list_infallible::<AiModel>().await {
            let id = api.id;
            let api = api.object;
            let api = Arc::new(AiApiConfig {
                id: api.name,
                api_type: match api.model_type {
                    AiModelType::Chat => ApiType::ChatCompletion,
                    AiModelType::Text => ApiType::TextCompletion,
                },
                url: api.url,
                headers: api
                    .http_auth
                    .build_headers(api.http_headers, "application/json".into())
                    .await
                    .map_err(|err| {
                        bp.build_error(id, format!("Unable to build HTTP headers: {}", err))
                    })
                    .unwrap_or_default(),
                model: api.model,
                timeout: api.timeout.into_inner(),
                tls_allow_invalid_certs: api.allow_invalid_certs,
                default_temperature: api.temperature.into_inner(),
            });
            ai_apis.insert(api.id.clone(), api.clone());
            ai_apis_ids.insert(id.id().id(), api);
        }

        // Build the enterprise configuration
        let mut enterprise = Enterprise {
            license,
            deleted_items_retention: dr
                .archive_deleted_items_for
                .map(|retention| retention.into_inner()),
            deleted_accounts_retention: dr
                .archive_deleted_accounts_for
                .map(|retention| retention.into_inner()),
            logo_url,
            metrics_alerts: Default::default(),
            spam_filter_llm: SpamFilterLlmConfig::parse(bp, &ai_apis_ids).await,
            ai_apis,
            template_calendar_alarm: None,
            template_scheduling_email: None,
            template_scheduling_web: None,
            trace_retention: dr.hold_traces_for.map(|d| d.into_inner()),
            metrics_retention: dr.hold_metrics_for.map(|d| d.into_inner()),
            metrics_interval: dr.metrics_collection_interval.into(),
        };

        // Parse metric alerts
        for alert in bp.list_infallible::<Alert>().await {
            let id = alert.id;
            let alert = alert.object;

            if !alert.enable {
                continue;
            }
            let condition = bp.compile_expr(id, &alert.ctx_condition()).default;
            let mut method = Vec::with_capacity(1);
            if let structs::AlertEmail::Enabled(alert) = alert.email_alert {
                method.push(AlertMethod::Email {
                    from_name: alert.from_name,
                    from_addr: alert.from_address,
                    to: alert.to.into_inner(),
                    subject: AlertContent::new(&alert.subject),
                    body: AlertContent::new(&alert.body),
                });
            }
            if let structs::AlertEvent::Enabled(alert) = alert.event_alert {
                method.push(AlertMethod::Event {
                    message: alert.event_message.as_deref().map(AlertContent::new),
                });
            }

            enterprise.metrics_alerts.push(MetricAlert {
                id,
                condition,
                method,
            });
        }

        // Parse templates
        let sched = bp.setting_infallible::<CalendarScheduling>().await;
        let alarm = bp.setting_infallible::<CalendarAlarm>().await;

        for (template, value, object, property) in [
            (
                alarm.template,
                &mut enterprise.template_calendar_alarm,
                ObjectType::CalendarAlarm.singleton(),
                Property::Template,
            ),
            (
                sched.email_template,
                &mut enterprise.template_scheduling_email,
                ObjectType::CalendarScheduling.singleton(),
                Property::EmailTemplate,
            ),
            (
                sched.http_rsvp_template,
                &mut enterprise.template_scheduling_web,
                ObjectType::CalendarScheduling.singleton(),
                Property::HttpRsvpTemplate,
            ),
        ] {
            if let Some(template) = template {
                match Template::parse(&template) {
                    Ok(template) => *value = Some(template),
                    Err(err) => {
                        bp.invalid_property(object, property, format!("Invalid template: {err}"));
                    }
                }
            }
        }

        Some(enterprise)
    }
}

impl SpamFilterLlmConfig {
    pub async fn parse(
        bp: &mut Bootstrap,
        models: &AHashMap<u64, Arc<AiApiConfig>>,
    ) -> Option<Self> {
        match bp.setting_infallible::<SpamLlm>().await {
            SpamLlm::Enable(llm) => {
                let Some(model) = models.get(&llm.model_id.id()).cloned() else {
                    bp.build_error(
                        ObjectType::SpamLlm.singleton(),
                        format!("Model {:?} not found in AI API configuration", llm.model_id),
                    );
                    return None;
                };
                Some(SpamFilterLlmConfig {
                    model,
                    temperature: llm.temperature.into_inner(),
                    prompt: llm.prompt,
                    separator: llm.separator.chars().next().unwrap_or(','),
                    index_category: llm.response_pos_category as usize,
                    index_confidence: llm.response_pos_confidence.map(|v| v as usize),
                    index_explanation: llm.response_pos_explanation.map(|v| v as usize),
                    categories: llm
                        .categories
                        .iter()
                        .map(|v| v.trim().to_uppercase())
                        .collect(),
                    confidence: llm
                        .confidence
                        .iter()
                        .map(|v| v.trim().to_uppercase())
                        .collect(),
                })
            }
            SpamLlm::Disable => None,
        }
    }
}

impl AlertContent {
    fn new(value: &str) -> Self {
        let mut tokens = Vec::new();
        let mut value = value.chars().peekable();
        let mut buf = String::new();

        while let Some(ch) = value.next() {
            if ch == '%' && value.peek() == Some(&'{') {
                value.next();

                let mut var_name = String::new();
                let mut found_curly = false;

                for ch in value.by_ref() {
                    if ch == '}' {
                        found_curly = true;
                        break;
                    }
                    var_name.push(ch);
                }

                if found_curly && value.peek() == Some(&'%') {
                    value.next();
                    if let Some(event_type) =
                        MetricType::parse(&var_name).map(AlertContentToken::Metric)
                    {
                        if !buf.is_empty() {
                            tokens.push(AlertContentToken::Text(std::mem::take(&mut buf)));
                        }
                        tokens.push(event_type);
                    } else {
                        buf.push('%');
                        buf.push('{');
                        buf.push_str(&var_name);
                        buf.push('}');
                        buf.push('%');
                    }
                } else {
                    buf.push('%');
                    buf.push('{');
                    buf.push_str(&var_name);
                }
            } else {
                buf.push(ch);
            }
        }

        if !buf.is_empty() {
            tokens.push(AlertContentToken::Text(buf));
        }

        AlertContent(tokens)
    }
}
