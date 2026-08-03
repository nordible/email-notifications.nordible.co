/*
 * SPDX-FileCopyrightText: 2026 Nordible Solutions <mail@nordible.co>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

// SPDX-SnippetBegin
// SPDX-FileCopyrightText: 2026 Nordible Solutions <mail@nordible.co>
// SPDX-License-Identifier: LicenseRef-SEL
#[cfg(feature = "enterprise")]
pub mod telemetry;
// SPDX-SnippetEnd
pub mod diagnose;
pub mod plans;

use crate::{
    api::diagnose::{DeliveryStage, spawn_delivery_diagnose},
    auth::{
        authenticate::Authenticator, oauth::auth::OAuthApiHandler, permissions::AccountApiHandler,
    },
};
use common::{
    Server,
    auth::{AccessToken, oauth::GrantType},
    manager::application::Resource,
};
use http_body_util::{StreamBody, combinators::BoxBody};
use http_proto::{
    HttpRequest, HttpResponse, HttpSessionData, ToHttpResponse,
    request::{decode_path_element, fetch_body},
};
use hyper::{
    Method, StatusCode,
    header::{self, CONTENT_ENCODING},
};
use jmap::api::{ToJmapHttpResponse, ToRequestError};
use jmap_proto::error::request::RequestError;
use registry::schema::enums::Permission;
use registry::types::id::ObjectId;
use std::time::Duration;
use utils::url_params::UrlParams;

pub trait ManagementApi: Sync + Send {
    fn handle_api_request(
        &self,
        req: &mut HttpRequest,
        session: &HttpSessionData,
    ) -> impl Future<Output = trc::Result<HttpResponse>> + Send;

    fn management_access_token(
        &self,
        req: &HttpRequest,
        session: &HttpSessionData,
    ) -> impl Future<Output = trc::Result<AccessToken>> + Send;
}

impl ManagementApi for Server {
    #[allow(unused_variables)]
    async fn handle_api_request(
        &self,
        req: &mut HttpRequest,
        session: &HttpSessionData,
    ) -> trc::Result<HttpResponse> {
        let is_post = req.method() == Method::POST;
        let body = if is_post {
            fetch_body(req, 1024 * 1024, session.session_id).await
        } else {
            None
        };
        let path = req.uri().path().split('/').skip(2).collect::<Vec<_>>();

        match path.first().copied().unwrap_or_default() {
            "signup" if is_post => {
                self.is_http_anonymous_request_allowed(session.remote_ip)
                    .await?;
                Box::pin(handle_signup_request(
                    self,
                    session,
                    body.ok_or_else(|| trc::LimitEvent::SizeRequest.into_err())?,
                ))
                .await
            }
            "update-capacity" if is_post => {
                self.is_http_anonymous_request_allowed(session.remote_ip)
                    .await?;
                Box::pin(handle_update_capacity_request(
                    self,
                    body.ok_or_else(|| trc::LimitEvent::SizeRequest.into_err())?,
                ))
                .await
            }
            "auth" if is_post => {
                self.is_http_anonymous_request_allowed(session.remote_ip)
                    .await?;
                match path.get(1).copied() {
                    Some("reset-request") => {
                        Box::pin(handle_reset_request(
                            self,
                            body.ok_or_else(|| trc::LimitEvent::SizeRequest.into_err())?,
                        ))
                        .await
                    }
                    Some("reset") => {
                        Box::pin(handle_reset_confirm(
                            self,
                            body.ok_or_else(|| trc::LimitEvent::SizeRequest.into_err())?,
                        ))
                        .await
                    }
                    _ => {
                        Box::pin(self.handle_login_request(
                            session,
                            body.ok_or_else(|| trc::LimitEvent::SizeRequest.into_err())?,
                        ))
                        .await
                    }
                }
            }
            "discover" => {
                if let Some(email) = path.get(1).copied() {
                    self.is_http_anonymous_request_allowed(session.remote_ip)
                        .await?;
                    self.handle_discover_request(session, decode_path_element(email).as_ref())
                        .await
                } else {
                    Err(trc::ResourceEvent::NotFound.into_err())
                }
            }
            "tenant" => {
                if let Some(identifier) = path.get(1).copied() {
                    self.is_http_anonymous_request_allowed(session.remote_ip)
                        .await?;
                    Box::pin(handle_tenant_info_request(
                        self,
                        decode_path_element(identifier).as_ref(),
                    ))
                    .await
                } else {
                    Err(trc::ResourceEvent::NotFound.into_err())
                }
            }
            "account" => {
                // Authenticate request
                let (_in_flight, access_token) = self.authenticate_headers(req, session).await?;
                self.handle_account_request(&access_token).await
            }
            "schema" => {
                // Authenticate request
                let (_in_flight, access_token) = self.authenticate_headers(req, session).await?;
                static SCHEMA_JSON: &[u8] =
                    include_bytes!("../../../../resources/schema/schema.json.gz");
                const SCHEMA_HASH: &str =
                    include_str!("../../../../resources/schema/schema.json.sha256");

                let schema_hash = SCHEMA_HASH.trim();
                if path.get(1).is_some_and(|hash| hash == &schema_hash) {
                    Ok(Resource::new("application/json", SCHEMA_JSON.to_vec())
                        .into_http_response()
                        .with_immutable_cache()
                        .with_header(CONTENT_ENCODING, "gzip"))
                } else {
                    Ok(HttpResponse::redirect(format!("/api/schema/{schema_hash}")))
                }
            }
            "token" => {
                let access_token = self.management_access_token(req, session).await?;
                let account_id = access_token.account_id();
                match path.get(1).copied() {
                    // SPDX-SnippetBegin
                    // SPDX-FileCopyrightText: 2026 Nordible Solutions <mail@nordible.co>
                    // SPDX-License-Identifier: LicenseRef-SEL
                    #[cfg(feature = "enterprise")]
                    Some("tracing") if self.core.is_enterprise_edition() => {
                        // Validate the access token
                        access_token.enforce_permission(Permission::LiveTracing)?;

                        // Issue a live telemetry token valid for 60 seconds
                        Ok(HttpResponse::new(StatusCode::OK)
                            .with_no_cache()
                            .with_text_body(
                                self.encode_access_token(
                                    GrantType::LiveTracing,
                                    account_id,
                                    self.account(account_id).await?.name(),
                                    60,
                                    None,
                                    None,
                                )
                                .await?,
                            ))
                    }
                    #[cfg(feature = "enterprise")]
                    Some("metrics") if self.core.is_enterprise_edition() => {
                        // Validate the access token
                        access_token.enforce_permission(Permission::LiveMetrics)?;

                        // Issue a live telemetry token valid for 60 seconds
                        Ok(HttpResponse::new(StatusCode::OK)
                            .with_no_cache()
                            .with_text_body(
                                self.encode_access_token(
                                    GrantType::LiveMetrics,
                                    account_id,
                                    self.account(account_id).await?.name(),
                                    60,
                                    None,
                                    None,
                                )
                                .await?,
                            ))
                    }
                    // SPDX-SnippetEnd
                    Some("delivery") => {
                        // Validate the access token
                        access_token.enforce_permission(Permission::LiveDeliveryTest)?;

                        // Issue a live telemetry token valid for 60 seconds
                        Ok(HttpResponse::new(StatusCode::OK)
                            .with_no_cache()
                            .with_text_body(
                                self.encode_access_token(
                                    GrantType::LiveDelivery,
                                    account_id,
                                    self.account(account_id).await?.name(),
                                    60,
                                    None,
                                    None,
                                )
                                .await?,
                            ))
                    }
                    Some("tracing") | Some("metrics") => {
                        Err(trc::ResourceEvent::NotFound
                            .ctx(trc::Key::Details, "Enterprise feature"))
                    }
                    _ => Err(trc::ResourceEvent::NotFound.into_err()),
                }
            }
            "live" => {
                let access_token = self.management_access_token(req, session).await?;
                let params = UrlParams::new(req.uri().query());
                let account_id = access_token.account_id();

                match (
                    path.get(1).copied().unwrap_or_default(),
                    path.get(2).copied(),
                    req.method(),
                ) {
                    ("delivery", Some(target), &Method::GET) => {
                        // Validate the access token
                        access_token.enforce_permission(Permission::LiveDeliveryTest)?;

                        let timeout = Duration::from_secs(
                            params
                                .parse::<u64>("timeout")
                                .filter(|interval| *interval >= 1)
                                .unwrap_or(30),
                        );

                        let mut rx = spawn_delivery_diagnose(
                            self.clone(),
                            decode_path_element(target).to_lowercase(),
                            timeout,
                        );

                        Ok(HttpResponse::new(StatusCode::OK)
                            .with_content_type("text/event-stream")
                            .with_cache_control("no-store")
                            .with_stream_body(BoxBody::new(StreamBody::new(
                                async_stream::stream! {
                                    while let Some(stage) = rx.recv().await {
                                        yield Ok(stage.to_frame());
                                    }
                                    yield Ok(DeliveryStage::Completed.to_frame());
                                },
                            ))))
                    }
                    // SPDX-SnippetBegin
                    // SPDX-FileCopyrightText: 2026 Nordible Solutions <mail@nordible.co>
                    // SPDX-License-Identifier: LicenseRef-SEL
                    #[cfg(feature = "enterprise")]
                    ("tracing", _, &Method::GET) if self.core.is_enterprise_edition() => {
                        use crate::api::telemetry::TelemetryApi;

                        self.handle_telemetry_api_request(req, true, &access_token)
                            .await
                    }
                    #[cfg(feature = "enterprise")]
                    ("metrics", _, &Method::GET) if self.core.is_enterprise_edition() => {
                        use crate::api::telemetry::TelemetryApi;

                        self.handle_telemetry_api_request(req, false, &access_token)
                            .await
                    }
                    // SPDX-SnippetEnd
                    ("tracing" | "metrics", _, &Method::GET) => {
                        Err(trc::ResourceEvent::NotFound
                            .ctx(trc::Key::Details, "Enterprise feature"))
                    }
                    _ => Err(trc::ResourceEvent::NotFound.into_err()),
                }
            }
            _ => Err(trc::ResourceEvent::NotFound.into_err()),
        }
    }

    async fn management_access_token(
        &self,
        req: &HttpRequest,
        session: &HttpSessionData,
    ) -> trc::Result<AccessToken> {
        let params = UrlParams::new(req.uri().query());
        if let Some(token) = params.get("token") {
            let path = req.uri().path();
            let grant = if path.starts_with("/api/live/delivery") {
                Some((GrantType::LiveDelivery, Permission::LiveDeliveryTest))
            } else {
                // SPDX-SnippetBegin
                // SPDX-FileCopyrightText: 2026 Nordible Solutions <mail@nordible.co>
                // SPDX-License-Identifier: LicenseRef-SEL
                #[cfg(feature = "enterprise")]
                {
                    if self.core.is_enterprise_edition() {
                        if path.starts_with("/api/live/tracing") {
                            Some((GrantType::LiveTracing, Permission::LiveTracing))
                        } else if path.starts_with("/api/live/metrics") {
                            Some((GrantType::LiveMetrics, Permission::LiveMetrics))
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                }
                // SPDX-SnippetEnd
                #[cfg(not(feature = "enterprise"))]
                {
                    None
                }
            };

            if let Some((grant_type, permission)) = grant {
                self.validate_access_token(grant_type.into(), token)
                    .await
                    .map(|token_info| {
                        AccessToken::from_permissions(token_info.account_id, [permission])
                    })
            } else {
                self.authenticate_headers(req, session)
                    .await
                    .map(|(_, token)| token)
            }
        } else {
            self.authenticate_headers(req, session)
                .await
                .map(|(_, token)| token)
        }
    }
}

pub trait ToManageHttpResponse {
    fn into_http_response(self) -> HttpResponse;
}

impl ToManageHttpResponse for &trc::Error {
    fn into_http_response(self) -> HttpResponse {
        match self.as_ref() {
            trc::EventType::Auth(
                trc::AuthEvent::Failed | trc::AuthEvent::Error | trc::AuthEvent::TokenExpired,
            ) => HttpResponse::unauthorized(true),
            trc::EventType::Resource(trc::ResourceEvent::NotFound) => {
                RequestError::not_found().into_http_response()
            }
            _ => self.to_request_error().into_http_response(),
        }
    }
}

pub trait UnauthorizedResponse {
    fn unauthorized(include_realms: bool) -> Self;
}

impl UnauthorizedResponse for HttpResponse {
    fn unauthorized(include_realms: bool) -> Self {
        (if include_realms {
            HttpResponse::new(StatusCode::UNAUTHORIZED)
                .with_header(
                    header::WWW_AUTHENTICATE,
                    "Bearer realm=\"Nordible Mail Server\", resource_metadata=\"/.well-known/oauth-protected-resource\"",
                )
                .with_header(header::WWW_AUTHENTICATE, "Basic realm=\"Nordible Mail Server\"")
        } else {
            HttpResponse::new(StatusCode::UNAUTHORIZED)
        })
        .with_content_type("application/problem+json")
        .with_text_body(serde_json::to_string(&RequestError::unauthorized()).unwrap_or_default())
    }
}

#[derive(Default, serde::Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct SignupRequest {
    tenant_name: String,
    domain_name: String,
    admin_username: String,
    admin_password: String,
    recovery_email: Option<String>,
    plan: Option<String>,
    mailbox_quota_bytes: Option<u64>,
    quantity: Option<u64>,
    dkim_selector: Option<String>,
    dkim_private_key: Option<String>,
    subscription_id: Option<String>,
    currency: Option<String>,
}

pub async fn handle_signup_request(
    server: &Server,
    _session: &HttpSessionData,
    body: Vec<u8>,
) -> trc::Result<HttpResponse> {
    let request: SignupRequest = serde_json::from_slice(&body).map_err(|err| {
        trc::EventType::Resource(trc::ResourceEvent::BadParameters).from_json_error(err)
    })?;

    println!("[SIGNUP API] Received signup for tenant '{}' ({}), plan: '{:?}', quantity: '{:?}', subscriptionId: '{:?}', currency: '{:?}'", 
        request.tenant_name, request.domain_name, request.plan, request.quantity, request.subscription_id, request.currency);

    let domain_name = request.domain_name.trim().to_ascii_lowercase();
    if domain_name.is_empty() || request.tenant_name.trim().is_empty() || request.admin_username.trim().is_empty() || request.admin_password.trim().is_empty() {
        return Err(trc::ResourceEvent::BadParameters.into_err().details("All fields are required."));
    }

    // Determine plan tier and storage quotas matching marketing site offerings
    let plan_tier = plans::PlanTier::from_str(request.plan.as_deref().unwrap_or("basic"));
    let mailbox_quota = request.mailbox_quota_bytes.unwrap_or(plans::DEFAULT_MAILBOX_QUOTA_BYTES);
    let max_accounts = request.quantity.unwrap_or(1);

    // Validate domain format simply (must contain at least one dot)
    if !domain_name.contains('.') || domain_name.len() < 4 {
        return Err(trc::ResourceEvent::BadParameters.into_err().details("Invalid domain name."));
    }

    // Check if domain already exists
    if server.domain(&domain_name).await?.is_some() {
        return Err(trc::ResourceEvent::BadParameters.into_err().details("Domain is already registered."));
    }

    // Construct Tenant with explicit plan_tier, subscription_id, currency, and storage quotas
    let tenant = registry::schema::structs::Tenant {
        name: request.tenant_name.trim().to_string(),
        created_at: registry::types::datetime::UTCDateTime::now(),
        plan_tier: Some(plan_tier.as_str().to_string()),
        subscription_id: request.subscription_id.as_ref().map(|s| s.trim().to_string()),
        currency: request.currency.as_ref().map(|s| s.trim().to_string()),
        logo: None,
        quotas: utils::map::vec_map::VecMap::from_iter([
            (registry::schema::enums::TenantStorageQuota::MaxAccounts, max_accounts),
            (registry::schema::enums::TenantStorageQuota::MaxDiskQuota, mailbox_quota),
        ]),
        ..Default::default()
    };

    let tenant_obj = tenant.into();
    let tenant_write_result = server.registry()
        .write(store::registry::write::RegistryWrite::insert(&tenant_obj))
        .await?;
    let tenant_id = match tenant_write_result {
        store::registry::write::RegistryWriteResult::Success(id) => id,
        err => return Err(trc::ResourceEvent::BadParameters.into_err().details(format!("Failed to create tenant: {err:?}"))),
    };

    // Construct Domain
    let domain = registry::schema::structs::Domain {
        name: domain_name.clone(),
        is_enabled: true,
        created_at: registry::types::datetime::UTCDateTime::now(),
        member_tenant_id: Some(tenant_id),
        ..Default::default()
    };

    let domain_obj = domain.clone().into();
    let domain_write_result = server.registry()
        .write(store::registry::write::RegistryWrite::insert(&domain_obj))
        .await?;
    let domain_id = match domain_write_result {
        store::registry::write::RegistryWriteResult::Success(id) => id,
        err => return Err(trc::ResourceEvent::BadParameters.into_err().details(format!("Failed to create domain: {err:?}"))),
    };

    // Construct Account with plan storage quota
    let password_hash = directory::core::secret::hash_secret(
        server.core.network.security.password_hash_algorithm,
        request.admin_password.into_bytes(),
    )
    .await
    .unwrap_or_default();

    let account = registry::schema::structs::Account::User(registry::schema::structs::UserAccount {
        name: request.admin_username.trim().to_string(),
        domain_id,
        credentials: registry::types::list::List::from_iter([
            registry::schema::structs::Credential::Password(registry::schema::structs::PasswordCredential {
                credential_id: types::id::Id::new(0),
                secret: password_hash,
                ..Default::default()
            })
        ]),
        created_at: registry::types::datetime::UTCDateTime::now(),
        member_tenant_id: Some(tenant_id),
        roles: registry::schema::structs::UserRoles::Admin,
        quotas: utils::map::vec_map::VecMap::from_iter([
            (registry::schema::enums::StorageQuota::MaxDiskQuota, mailbox_quota),
        ]),
        recovery_email: request.recovery_email.clone(),
        description: None,
        ..Default::default()
    });

    let account_obj = account.into();
    let account_write_result = server.registry()
        .write(store::registry::write::RegistryWrite::insert(&account_obj))
        .await?;
    let _account_id = match account_write_result {
        store::registry::write::RegistryWriteResult::Success(id) => id,
        err => return Err(trc::ResourceEvent::BadParameters.into_err().details(format!("Failed to create account: {err:?}"))),
    };

    let selector_str = request.dkim_selector.as_deref().unwrap_or("dkim").to_string();
    let private_key_pem = if let Some(pk) = request.dkim_private_key {
        pk.trim().to_string()
    } else {
        match common::network::dkim::generate_dkim_private_key(registry::schema::enums::DkimSignatureType::Dkim1RsaSha256).await {
            Ok(Ok(pem)) => pem,
            _ => String::new(),
        }
    };

    let mut dkim_full_value = String::new();
    if !private_key_pem.is_empty() {
        let dkim_sig = registry::schema::structs::DkimSignature::Dkim1RsaSha256(
            registry::schema::structs::Dkim1Signature {
                domain_id,
                member_tenant_id: Some(tenant_id),
                selector: selector_str.clone(),
                private_key: registry::schema::structs::SecretText::Text(
                    registry::schema::structs::SecretTextValue {
                        secret: private_key_pem,
                    }
                ),
                created_at: registry::types::datetime::UTCDateTime::now(),
                stage: registry::schema::enums::DkimRotationStage::Active,
                canonicalization: registry::schema::enums::DkimCanonicalization::RelaxedSimple,
                ..Default::default()
            }
        );

        if let Ok(pub_key) = common::network::dkim::generate_dkim_public_key(&dkim_sig).await {
            dkim_full_value = format!("v=DKIM1; k=rsa; p={pub_key}");
        }

        let dkim_sig_obj = dkim_sig.into();
        server.registry()
            .write(store::registry::write::RegistryWrite::insert(&dkim_sig_obj))
            .await?;
    }

    // Clear negative caches so the newly created domain and account are queryable immediately
    server.inner.cache.domain_names_negative.clear();
    server.inner.cache.emails_negative.clear();

    let full_username = format!("{}@{}", request.admin_username.trim(), domain_name);

    let admin_host = server.core.network.server_name.as_str();
    let bind_zone = server.build_bind_dns_records(domain_id, &domain).await.unwrap_or_default();

    let dns_records = serde_json::json!({
        "mx": format!("{} (Priority 10)", admin_host),
        "mxHost": domain_name.clone(),
        "mxValue": admin_host,
        "spfHost": domain_name.clone(),
        "spfValue": format!("v=spf1 include:{} ~all", admin_host),
        "dkimSelector": selector_str,
        "dkimHost": format!("{}._domainkey.{}", selector_str, domain_name),
        "dkimValue": if dkim_full_value.is_empty() { "v=DKIM1; k=rsa; p=MIIBIj...".to_string() } else { dkim_full_value },
        "dmarcHost": format!("_dmarc.{}", domain_name),
        "dmarcValue": "v=DMARC1; p=none;",
        "autodiscoverHost": format!("autodiscover.{}", domain_name),
        "autodiscoverValue": admin_host,
        "autoconfigHost": format!("autoconfig.{}", domain_name),
        "autoconfigValue": admin_host,
        "srvImapHost": format!("_imaps._tcp.{}", domain_name),
        "srvImapValue": format!("0 1 993 {}.", admin_host),
        "srvSubmissionHost": format!("_submission._tcp.{}", domain_name),
        "srvSubmissionValue": format!("0 1 587 {}.", admin_host),
        "mtaStsHost": format!("mta-sts.{}", domain_name),
        "mtaStsValue": admin_host,
        "mtaStsTxtHost": format!("_mta-sts.{}", domain_name),
        "mtaStsTxtValue": "v=STSv1; id=20260724",
        "tlsRptHost": format!("_smtp._tls.{}", domain_name),
        "tlsRptValue": format!("v=TLSRPTv1; rua=mailto:tls-reports@{}", domain_name),
        "bindZone": bind_zone,
    });

    let resp = serde_json::json!({
        "success": true,
        "username": full_username,
        "recoveryEmail": request.recovery_email,
        "dnsRecords": dns_records,
    });

    Ok(HttpResponse::new(StatusCode::OK)
        .with_no_cache()
        .with_content_type("application/json")
        .with_text_body(resp.to_string()))
}

use std::sync::{LazyLock, Mutex};
use std::collections::HashMap;
use std::time::Instant;

struct ResetToken {
    code: String,
    expires_at: Instant,
}

static RESET_TOKENS: LazyLock<Mutex<HashMap<String, ResetToken>>> = LazyLock::new(|| {
    Mutex::new(HashMap::new())
});

fn generate_code() -> String {
    use std::time::SystemTime;
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let val = (nanos % 900_000) + 100_000;
    format!("{}", val)
}

#[derive(serde::Deserialize)]
struct ResetRequest {
    email: String,
}

pub async fn handle_reset_request(
    server: &Server,
    body: Vec<u8>,
) -> trc::Result<HttpResponse> {
    let request: ResetRequest = serde_json::from_slice(&body).map_err(|err| {
        trc::EventType::Resource(trc::ResourceEvent::BadParameters).from_json_error(err)
    })?;

    let email = request.email.trim().to_ascii_lowercase();
    if email.is_empty() || !email.contains('@') {
        return Err(trc::ResourceEvent::BadParameters.into_err().details("Invalid email address."));
    }

    let _account_id = match server.account_id_from_email(&email, false).await? {
        Some(id) => types::id::Id::new(id.into()),
        None => {
            return Err(trc::ResourceEvent::BadParameters.into_err().details("Account not found."));
        }
    };

    let code = generate_code();
    {
        let mut tokens = RESET_TOKENS.lock().unwrap();
        tokens.insert(
            email.clone(),
            ResetToken {
                code: code.clone(),
                expires_at: Instant::now() + Duration::from_secs(600),
            },
        );
    }

    println!("[PASSWORD RESET] Verification code for {}: {}", email, code);

    let resp = serde_json::json!({
        "success": true,
        "message": "Verification code generated successfully.",
        "dev_token": code,
    });

    Ok(HttpResponse::new(StatusCode::OK)
        .with_no_cache()
        .with_content_type("application/json")
        .with_text_body(resp.to_string()))
}

#[derive(serde::Deserialize)]
struct ResetConfirmRequest {
    email: String,
    token: String,
    password: String,
}

pub async fn handle_reset_confirm(
    server: &Server,
    body: Vec<u8>,
) -> trc::Result<HttpResponse> {
    let request: ResetConfirmRequest = serde_json::from_slice(&body).map_err(|err| {
        trc::EventType::Resource(trc::ResourceEvent::BadParameters).from_json_error(err)
    })?;

    let email = request.email.trim().to_ascii_lowercase();
    let token = request.token.trim();
    let password = request.password.trim();

    if email.is_empty() || token.is_empty() || password.is_empty() {
        return Err(trc::ResourceEvent::BadParameters.into_err().details("All fields are required."));
    }

    {
        let mut tokens = RESET_TOKENS.lock().unwrap();
        if let Some(entry) = tokens.get(&email) {
            if entry.expires_at < Instant::now() {
                tokens.remove(&email);
                return Err(trc::ResourceEvent::BadParameters.into_err().details("Reset token has expired."));
            }
            if entry.code != token {
                return Err(trc::ResourceEvent::BadParameters.into_err().details("Invalid reset token."));
            }
        } else {
            return Err(trc::ResourceEvent::BadParameters.into_err().details("No password reset requested for this email."));
        }
        tokens.remove(&email);
    }

    let account_id = match server.account_id_from_email(&email, false).await? {
        Some(id) => types::id::Id::new(id.into()),
        None => {
            return Err(trc::ResourceEvent::BadParameters.into_err().details("Account not found."));
        }
    };

    let old_account_obj = match server.registry().get(ObjectId::new(registry::schema::prelude::ObjectType::Account, account_id)).await? {
        Some(obj) => obj,
        None => {
            return Err(trc::ResourceEvent::BadParameters.into_err().details("Failed to load account details."));
        }
    };

    let mut updated_account_obj = old_account_obj.clone();
    if let registry::schema::prelude::ObjectInner::Account(registry::schema::structs::Account::User(ref mut user)) = updated_account_obj.inner {
        let password_hash = directory::core::secret::hash_secret(
            server.core.network.security.password_hash_algorithm,
            password.to_string().into_bytes(),
        )
        .await
        .unwrap_or_default();

        user.set_password(password_hash);
    } else {
        return Err(trc::ResourceEvent::BadParameters.into_err().details("Only user accounts can reset passwords."));
    }

    let write_result = server.registry()
        .write(store::registry::write::RegistryWrite::update(
            account_id,
            &updated_account_obj,
            &old_account_obj,
        ))
        .await?;

    match write_result {
        store::registry::write::RegistryWriteResult::Success(id) => {
            let mut invalidator = common::cache::invalidate::CacheInvalidationBuilder::default();
            invalidator.process_update(id, &old_account_obj, &updated_account_obj);
            server.invalidate_caches(invalidator).await?;
        }
        err => return Err(trc::ResourceEvent::BadParameters.into_err().details(format!("Failed to update account: {err:?}"))),
    };

    let resp = serde_json::json!({
        "success": true,
        "message": "Password reset successfully."
    });

    Ok(HttpResponse::new(StatusCode::OK)
        .with_no_cache()
        .with_content_type("application/json")
        .with_text_body(resp.to_string()))
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpdateCapacityRequest {
    subscription_id: Option<String>,
    tenant_name: Option<String>,
    max_accounts: u64,
    max_disk_quota: Option<u64>,
}

pub async fn handle_update_capacity_request(
    server: &Server,
    body: Vec<u8>,
) -> trc::Result<HttpResponse> {
    let request: UpdateCapacityRequest = serde_json::from_slice(&body).map_err(|err| {
        trc::EventType::Resource(trc::ResourceEvent::BadParameters).from_json_error(err)
    })?;

    let sub_id = request.subscription_id.as_deref().unwrap_or_default().trim();
    let tenant_name = request.tenant_name.as_deref().unwrap_or_default().trim();

    if (sub_id.is_empty() && tenant_name.is_empty()) || request.max_accounts < 1 {
        return Err(trc::ResourceEvent::BadParameters.into_err().details("subscriptionId/tenantName and valid maxAccounts >= 1 are required."));
    }

    let query = store::registry::RegistryQuery::new(registry::schema::prelude::ObjectType::Tenant);
    let tenant_ids: Vec<types::id::Id> = server.registry().query(query).await?;
    let mut found_tenant_id = None;

    for id in tenant_ids {
        if let Some(tenant) = server.registry().object::<registry::schema::prelude::Tenant>(id).await? {
            let matches_sub = !sub_id.is_empty() && tenant.subscription_id.as_deref() == Some(sub_id);
            let matches_name = !tenant_name.is_empty() && tenant.name.eq_ignore_ascii_case(tenant_name);
            if matches_sub || matches_name {
                found_tenant_id = Some(id);
                break;
            }
        }
    }

    let tenant_id = match found_tenant_id {
        Some(id) => id,
        None => return Err(trc::ResourceEvent::BadParameters.into_err().details("Tenant not found.")),
    };

    let old_obj = match server.registry().get(ObjectId::new(registry::schema::prelude::ObjectType::Tenant, tenant_id)).await? {
        Some(obj) => obj,
        None => return Err(trc::ResourceEvent::BadParameters.into_err().details("Tenant not found.")),
    };

    let mut new_obj = old_obj.clone();
    if let registry::schema::prelude::ObjectInner::Tenant(ref mut tenant) = new_obj.inner {
        tenant.quotas.set(registry::schema::enums::TenantStorageQuota::MaxAccounts, request.max_accounts);
        
        if let Some(max_disk_bytes) = request.max_disk_quota {
            tenant.quotas.set(registry::schema::enums::TenantStorageQuota::MaxDiskQuota, max_disk_bytes);
        }
    } else {
        return Err(trc::ResourceEvent::BadParameters.into_err().details("Failed to parse stored tenant object."));
    }

    let write_res = server.registry().write(store::registry::write::RegistryWrite::update(tenant_id, &new_obj, &old_obj)).await?;

    match write_res {
        store::registry::write::RegistryWriteResult::Success(id) => {
            let mut invalidator = common::cache::invalidate::CacheInvalidationBuilder::default();
            invalidator.process_update(id, &old_obj, &new_obj);
            server.invalidate_caches(invalidator).await?;
        }
        err => return Err(trc::ResourceEvent::BadParameters.into_err().details(format!("Failed to update tenant capacity: {err:?}"))),
    }

    let resp = serde_json::json!({
        "success": true,
        "subscriptionId": request.subscription_id,
        "tenantName": request.tenant_name,
        "maxAccounts": request.max_accounts,
        "message": format!("Tenant account limit updated to {} seats.", request.max_accounts),
    });

    Ok(HttpResponse::new(StatusCode::OK)
        .with_no_cache()
        .with_content_type("application/json")
        .with_text_body(resp.to_string()))
}

pub async fn handle_tenant_info_request(
    server: &Server,
    identifier: &str,
) -> trc::Result<HttpResponse> {
    let search_term = identifier.trim();
    if search_term.is_empty() {
        return Err(trc::ResourceEvent::BadParameters.into_err().details("Tenant domain or subscription ID is required."));
    }

    let query = store::registry::RegistryQuery::new(registry::schema::prelude::ObjectType::Tenant);
    let tenant_ids: Vec<types::id::Id> = server.registry().query(query).await?;

    for id in tenant_ids {
        if let Some(tenant) = server.registry().object::<registry::schema::prelude::Tenant>(id).await? {
            let matches_sub = tenant.subscription_id.as_deref() == Some(search_term);
            let matches_name = tenant.name.eq_ignore_ascii_case(search_term);
            if matches_sub || matches_name {
                let max_accounts = tenant.quotas.get(&registry::schema::enums::TenantStorageQuota::MaxAccounts).copied().unwrap_or(1);
                let resp = serde_json::json!({
                    "success": true,
                    "tenantName": tenant.name,
                    "domain": tenant.name,
                    "subscriptionId": tenant.subscription_id,
                    "currency": tenant.currency.as_deref().unwrap_or("INR"),
                    "maxAccounts": max_accounts,
                    "planId": tenant.plan_tier.as_deref().unwrap_or("basic"),
                });

                return Ok(HttpResponse::new(StatusCode::OK)
                    .with_no_cache()
                    .with_content_type("application/json")
                    .with_text_body(resp.to_string()));
            }
        }
    }

    Err(trc::ResourceEvent::BadParameters.into_err().details("Tenant not found."))
}


