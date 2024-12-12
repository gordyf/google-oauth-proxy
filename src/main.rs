use axum::{
    extract::{Query, State},
    response::{IntoResponse, Redirect},
    routing::get,
    Router,
};
use openidconnect::{
    core::{CoreClient, CoreProviderMetadata, CoreResponseType},
    reqwest::async_http_client,
    AuthenticationFlow, AuthorizationCode, CsrfToken, IssuerUrl, Nonce, RedirectUrl, Scope,
};
use serde::Deserialize;
use std::env;
use std::sync::Arc;

struct AppState {
    openid_client: CoreClient,
}

#[derive(Deserialize)]
struct AuthRequest {
    code: String,
}

async fn auth_redirect(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let client = &state.openid_client;

    let (auth_url, _csrf_token, _nonce) = client
        .authorize_url(
            AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .add_scope(Scope::new("email".to_string()))
        .url();

    Redirect::to(auth_url.as_str())
}

async fn callback(
    Query(query): Query<AuthRequest>,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let client = &state.openid_client;

    let token_result = client
        .exchange_code(AuthorizationCode::new(query.code.clone()))
        .request_async(async_http_client)
        .await;

    match token_result {
        Ok(_) => "Authenticated".to_string().into_response(),
        Err(err) => (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            format!("Error: {}", err),
        )
            .into_response(),
    }
}

#[tokio::main]
async fn main() {
    let provider_metadata = CoreProviderMetadata::discover_async(
        IssuerUrl::new("https://accounts.google.com".to_string()).expect("Invalid issuer URL"),
        async_http_client,
    )
    .await
    .expect("Failed to discover OpenID Connect provider metadata");

    let client_id = openidconnect::ClientId::new(env::var("CLIENT_ID").unwrap());
    let client_secret = openidconnect::ClientSecret::new(env::var("CLIENT_SECRET").unwrap());
    let redirect_url =
        RedirectUrl::new(env::var("CALLBACK_URL").unwrap()).expect("Invalid redirect URL");

    let openid_client =
        CoreClient::from_provider_metadata(provider_metadata, client_id, Some(client_secret))
            .set_redirect_uri(redirect_url);

    let app_state = Arc::new(AppState { openid_client });

    let app = Router::new()
        .route("/auth", get(auth_redirect))
        .route("/callback", get(callback))
        .with_state(app_state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
