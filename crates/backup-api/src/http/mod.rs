//! The v1 HTTP boundary. Blocking file and SQLite work stays off the listener.
mod auth;
mod input;

use crate::{Config, Control, ErrorCode, Job, Operation, SafeError, Supervisor, model::MAX_TIME};
use anyhow::{Context, Result, ensure};
use axum::{
    Json, Router,
    extract::{ConnectInfo, Request, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header, request::Parts},
    response::{IntoResponse, Response},
};
use serde::Serialize;
use std::{
    collections::HashMap,
    hash::Hash,
    net::{IpAddr, SocketAddr},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Instant,
};
use tokio::{net::TcpListener, sync::Semaphore};
use uuid::Uuid;

const API_VERSION: &str = "backupctl-api-v1";
const ARTIFACT_LIMIT: usize = 4096;

struct Service {
    control: Control,
    requests: Arc<Semaphore>,
    blocking: Arc<Semaphore>,
    actors: Buckets<Uuid>,
    logins: Buckets<IpAddr>,
    rejected: AtomicU64,
}

pub async fn serve_http(config: Config, supervised: bool) -> Result<()> {
    let address = config.listen;
    let (mut supervisor, control) = if supervised {
        let supervisor = Supervisor::open(config, std::env::current_exe()?).await?;
        let control = supervisor.control();
        (Some(supervisor), control)
    } else {
        (None, Control::read_only(config)?)
    };
    let service = Arc::new(Service {
        control: control.clone(),
        requests: Arc::new(Semaphore::new(32)),
        blocking: Arc::new(Semaphore::new(4)),
        actors: Buckets::new(20.0, 1.0, 4096),
        logins: Buckets::new(5.0, 5.0 / 60.0, 1024),
        rejected: AtomicU64::new(0),
    });
    let app = Router::new().fallback(handle).with_state(service);
    let listener = TcpListener::bind(address).await?;
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    let server = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
        tokio::select! { _ = term.recv() => {}, _ = interrupt.recv() => {} }
        control.stop_admission();
    });
    if let Some(supervisor) = supervisor.as_mut() {
        tokio::try_join!(async { Ok(server.await?) }, supervisor.serve())?;
    } else {
        server.await?;
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum Action {
    Login,
    Session,
    Logout,
    Health,
    Metrics,
    Profiles,
    Artifacts,
    Artifact(Uuid),
    Jobs,
    Job(Uuid),
    Cancel(Uuid),
    Intent(Uuid),
    Submit(Operation),
}

impl Action {
    fn resolve(parts: &Parts) -> Result<Self> {
        use Action::*;
        let path = parts.uri.path();
        let method = &parts.method;
        let action = match (method, path) {
            (&Method::POST, "/api/v1/session") => Login,
            (&Method::GET, "/api/v1/session") => Session,
            (&Method::DELETE, "/api/v1/session") => Logout,
            (&Method::GET, "/api/v1/health") => Health,
            (&Method::GET, "/api/v1/metrics") => Metrics,
            (&Method::GET, "/api/v1/profiles") => Profiles,
            (&Method::GET, "/api/v1/artifacts") => Artifacts,
            (&Method::GET, "/api/v1/jobs") => Jobs,
            (&Method::POST, "/api/v1/backups") => Submit(Operation::Backup),
            (&Method::POST, "/api/v1/inspections") => Submit(Operation::Inspection),
            (&Method::POST, "/api/v1/verifications") => Submit(Operation::Verification),
            (&Method::POST, "/api/v1/restore-plans") => Submit(Operation::RestorePlan),
            (&Method::POST, "/api/v1/restores") => Submit(Operation::Restore),
            (&Method::POST, "/api/v1/retention-previews") => Submit(Operation::RetentionPreview),
            (&Method::POST, "/api/v1/retention-runs") => Submit(Operation::RetentionRun),
            (&Method::POST, "/api/v1/artifact-protections") => {
                Submit(Operation::ArtifactProtection)
            }
            _ => {
                let path = path.strip_prefix("/api/v1/").context(ErrorCode::NotFound)?;
                let (resource, tail) = path.split_once('/').context(ErrorCode::NotFound)?;
                match (method, resource) {
                    (&Method::GET, "artifacts") if !tail.contains('/') => {
                        Artifact(input::id(tail)?)
                    }
                    (&Method::GET, "jobs") if !tail.contains('/') => Job(input::id(tail)?),
                    (&Method::GET, "intents") if !tail.contains('/') => Intent(input::id(tail)?),
                    (&Method::POST, "jobs") => {
                        let id = tail
                            .strip_suffix("/cancel")
                            .filter(|id| !id.contains('/'))
                            .context(ErrorCode::NotFound)?;
                        Cancel(input::id(id)?)
                    }
                    _ => anyhow::bail!(ErrorCode::NotFound),
                }
            }
        };
        Ok(action)
    }

    fn json(self) -> bool {
        matches!(self, Self::Login | Self::Cancel(_) | Self::Submit(_))
    }

    fn mutation(self) -> bool {
        self.json() || matches!(self, Self::Logout)
    }
}

async fn handle(State(service): State<Arc<Service>>, request: Request) -> Response {
    let id = Uuid::new_v4();
    let outcome = dispatch(service.clone(), id, request).await;
    match outcome {
        Ok(response) => response,
        Err(error) => {
            service.rejected.fetch_add(1, Ordering::Relaxed);
            error_response(
                id,
                error
                    .downcast_ref::<ErrorCode>()
                    .copied()
                    .unwrap_or(ErrorCode::InternalError),
            )
        }
    }
}

async fn dispatch(service: Arc<Service>, id: Uuid, request: Request) -> Result<Response> {
    let _request = service
        .requests
        .clone()
        .try_acquire_owned()
        .map_err(|_| ErrorCode::RateLimit)?;
    let (parts, body) = request.into_parts();
    let config = service.control.config();
    let host = input::single(&parts.headers, "host")?.context(ErrorCode::AccessDenied)?;
    ensure!(
        parts.uri.authority().is_none() && host.eq_ignore_ascii_case(config.host.as_str()),
        ErrorCode::AccessDenied
    );
    if let Some(origin) = input::single(&parts.headers, "origin")? {
        ensure!(origin == config.public_origin, ErrorCode::AccessDenied);
    }
    let action = Action::resolve(&parts)?;
    let page = if matches!(action, Action::Artifacts | Action::Jobs) {
        Some(input::page(parts.uri.query())?)
    } else {
        ensure!(parts.uri.query().is_none(), ErrorCode::InvalidRequest);
        None
    };
    if matches!(action, Action::Login) {
        auth::require_origin(&service.control, &parts.headers)?;
        let peer = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .context(ErrorCode::InternalError)?;
        service.logins.allow(peer.0.ip())?;
    }
    let fields = input::body(&parts.headers, body, action.json()).await?;
    let lane = service
        .blocking
        .clone()
        .try_acquire_owned()
        .map_err(|_| ErrorCode::RateLimit)?;
    tokio::task::spawn_blocking(move || {
        // A disconnected request cannot drop this permit while its work continues.
        let _lane = lane;
        serve_request(&service, id, action, &parts.headers, fields, page)
    })
    .await?
}

fn serve_request(
    service: &Service,
    id: Uuid,
    action: Action,
    headers: &HeaderMap,
    fields: input::Fields,
    page: Option<input::Page>,
) -> Result<Response> {
    let control = &service.control;
    let ok = |data| success(id, StatusCode::OK, data);
    if matches!(action, Action::Login) {
        let (session, cookie) = auth::login(control, headers, fields.login_token()?)?;
        let mut response = success(id, StatusCode::CREATED, session);
        response
            .headers_mut()
            .insert(header::SET_COOKIE, HeaderValue::from_str(&cookie)?);
        return Ok(response);
    }
    let identity = auth::authenticate(control, headers, action.mutation())?;
    service.actors.allow(identity.actor.actor_id)?;
    let actor = identity.actor;
    let authority = &identity.authority;
    use Action::*;
    match action {
        Login => unreachable!("login handled before authenticated dispatch"),
        Session => Ok(success(id, StatusCode::OK, identity.view())),
        Logout => {
            let cookie = identity.revoke(control)?;
            let mut response = ok(serde_json::json!({"revoked": true}));
            response
                .headers_mut()
                .insert(header::SET_COOKIE, HeaderValue::from_str(&cookie)?);
            Ok(response)
        }
        Health => {
            let ready = control.config().discovery_config().is_ok();
            Ok(ok(serde_json::json!({
                "ready": ready, "mode": "fixture", "production_enabled": false,
                "job_admission": ready && control.accepting(),
                "containment_verified": control.supervised(),
                "queue_depth": control.store()?.queue_depth()?,
            })))
        }
        Metrics => {
            ensure!(authority.admin(), ErrorCode::AccessDenied);
            let mut counters = control.store()?.metrics()?;
            counters.rejected_total = service.rejected.load(Ordering::Relaxed).min(MAX_TIME);
            Ok(success(id, StatusCode::OK, counters))
        }
        Profiles => Ok(ok(
            serde_json::json!({"items": control.config().profiles(authority)}),
        )),
        Artifacts => {
            let page = page.context(ErrorCode::InternalError)?;
            let items = public_root(control)?
                .map(|root| root.discover_public(ARTIFACT_LIMIT))
                .transpose()?
                .map(|items| items.context(ErrorCode::DiscoveryLimit))
                .transpose()?
                .unwrap_or_default();
            let mut items: Vec<_> = items
                .into_iter()
                .filter(|artifact| {
                    crate::model::uuid4(artifact.id)
                        && page.after.is_none_or(|after| artifact.id > after)
                })
                .take(page.limit + 1)
                .map(ArtifactView::from)
                .collect();
            let next_after = if items.len() > page.limit {
                items.pop();
                items.last().map(|artifact| artifact.artifact_id)
            } else {
                None
            };
            Ok(ok(
                serde_json::json!({"items": items, "next_after": next_after}),
            ))
        }
        Artifact(artifact) => {
            let root = public_root(control)?.context(ErrorCode::NotFound)?;
            let public = root
                .discover_public_id(artifact)?
                .context(ErrorCode::NotFound)?;
            Ok(success(id, StatusCode::OK, ArtifactView::from(public)))
        }
        Jobs => {
            let page = page.context(ErrorCode::InternalError)?;
            let (items, next) = control
                .store()?
                .page_jobs(actor, authority, page.after, page.limit)?;
            Ok(ok(serde_json::json!({"items": items, "next_after": next})))
        }
        Job(job) => Ok(success(id, StatusCode::OK, control.job(actor, job)?)),
        Intent(intent) => Ok(success(id, StatusCode::OK, control.intent(actor, intent)?)),
        Cancel(job) => {
            fields.empty()?;
            ensure!(authority.cancel(), ErrorCode::AccessDenied);
            Ok(success(
                id,
                StatusCode::OK,
                control.cancel(actor, job, idempotency_key(headers)?)?,
            ))
        }
        Submit(operation) => {
            ensure!(authority.allows(operation), ErrorCode::AccessDenied);
            let request = fields.worker_request(operation)?;
            let job = control.submit(actor, idempotency_key(headers)?, request)?;
            accepted(id, job)
        }
    }
}

fn idempotency_key(headers: &HeaderMap) -> Result<Uuid> {
    let value = input::single(headers, "idempotency-key")?.context(ErrorCode::InvalidRequest)?;
    input::id(value)
}

#[derive(Serialize)]
struct ArtifactView {
    artifact_id: Uuid,
    format: String,
    header_status: &'static str,
}

impl From<backup_local::PublicArtifact> for ArtifactView {
    fn from(artifact: backup_local::PublicArtifact) -> Self {
        Self {
            artifact_id: artifact.id,
            format: artifact.header_version.map_or_else(
                || "unsigned".to_owned(),
                |version| format!("signed-artifact-v{version}"),
            ),
            header_status: "unverified",
        }
    }
}

fn public_root(control: &Control) -> Result<Option<Arc<backup_local::ProtectedRoot>>> {
    let config = control.config().discovery_config()?;
    match backup_local::ProtectedRoot::open(&config, false) {
        Ok(root) => Ok(Some(root)),
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
        {
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

#[derive(Serialize)]
struct Success<T> {
    api_version: &'static str,
    request_id: Uuid,
    data: T,
}
#[derive(Serialize)]
struct Failure {
    api_version: &'static str,
    request_id: Uuid,
    error: SafeError,
}

fn success<T: Serialize>(id: Uuid, status: StatusCode, data: T) -> Response {
    no_store(
        (
            status,
            Json(Success {
                api_version: API_VERSION,
                request_id: id,
                data,
            }),
        )
            .into_response(),
    )
}

fn accepted(id: Uuid, job: Job) -> Result<Response> {
    if job.state.terminal() {
        return Ok(success(id, StatusCode::OK, job));
    }
    let location = HeaderValue::from_str(&job.url)?;
    let mut response = success(id, StatusCode::ACCEPTED, job);
    response.headers_mut().insert(header::LOCATION, location);
    response
        .headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from_static("2"));
    Ok(response)
}

fn error_response(id: Uuid, code: ErrorCode) -> Response {
    use ErrorCode::*;
    let status = match code {
        InvalidRequest => StatusCode::BAD_REQUEST,
        AuthRequired => StatusCode::UNAUTHORIZED,
        AccessDenied => StatusCode::FORBIDDEN,
        NotFound => StatusCode::NOT_FOUND,
        IdempotencyConflict | IntentConflict | ConfigChanged => StatusCode::CONFLICT,
        IntentExpired => StatusCode::GONE,
        PolicyRefused => StatusCode::UNPROCESSABLE_ENTITY,
        BodyTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
        UnsupportedMedia => StatusCode::UNSUPPORTED_MEDIA_TYPE,
        RateLimit | QueueFull => StatusCode::TOO_MANY_REQUESTS,
        NotReady | ContainmentUnavailable | ControlCapacity | DiscoveryLimit => {
            StatusCode::SERVICE_UNAVAILABLE
        }
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    let retryable = matches!(code, RateLimit | QueueFull | NotReady);
    let error = SafeError { code, retryable };
    let mut response = no_store(
        (
            status,
            Json(Failure {
                api_version: API_VERSION,
                request_id: id,
                error,
            }),
        )
            .into_response(),
    );
    if status == StatusCode::UNAUTHORIZED {
        response
            .headers_mut()
            .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    }
    if status == StatusCode::TOO_MANY_REQUESTS {
        response
            .headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
    }
    response
}

fn no_store(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

struct Bucket {
    tokens: f64,
    at: Instant,
}

struct Buckets<K> {
    entries: Mutex<HashMap<K, Bucket>>,
    burst: f64,
    refill: f64,
    max_keys: usize,
}

impl<K: Eq + Hash> Buckets<K> {
    fn new(burst: f64, refill: f64, max_keys: usize) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            burst,
            refill,
            max_keys,
        }
    }

    fn allow(&self, key: K) -> Result<()> {
        let time = Instant::now();
        let mut entries = self.entries.lock().map_err(|_| ErrorCode::InternalError)?;
        if !entries.contains_key(&key) && entries.len() >= self.max_keys {
            entries.retain(|_, bucket| {
                time.saturating_duration_since(bucket.at).as_secs_f64() * self.refill < self.burst
            });
            ensure!(entries.len() < self.max_keys, ErrorCode::RateLimit);
        }
        let bucket = entries.entry(key).or_insert(Bucket {
            tokens: self.burst,
            at: time,
        });
        let seconds = time.saturating_duration_since(bucket.at).as_secs_f64();
        bucket.tokens = (bucket.tokens + seconds * self.refill).min(self.burst);
        bucket.at = bucket.at.max(time);
        ensure!(bucket.tokens >= 1.0, ErrorCode::RateLimit);
        bucket.tokens -= 1.0;
        Ok(())
    }
}
