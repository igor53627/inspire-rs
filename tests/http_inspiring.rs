#![cfg(feature = "server")]

use std::net::SocketAddr;
use std::sync::Arc;

use axum::{extract::State, http::StatusCode, routing::post, Json, Router};
use inspire::math::GaussianSampler;
use inspire::params::InspireParams;
use inspire::pir::{
    extract_inspiring, query, respond_inspiring, respond_one_packing, setup, ClientQuery,
    EncodedDatabase, PackingMode, ServerCrs, ServerResponse,
};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;

#[derive(Clone)]
struct AppState {
    crs: ServerCrs,
    db: EncodedDatabase,
}

#[derive(Serialize, Deserialize)]
struct QueryResponse {
    response: ServerResponse,
    processing_time_ms: u64,
}

#[derive(Serialize, Deserialize)]
struct ErrorResponse {
    error: String,
}

async fn handle_query(
    State(state): State<Arc<AppState>>,
    Json(query): Json<ClientQuery>,
) -> Result<Json<QueryResponse>, (StatusCode, Json<ErrorResponse>)> {
    let response = match query.packing_mode {
        PackingMode::Inspiring => {
            if query.inspiring_packing_keys.is_none() {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: "InspiRING packing keys missing (set packing_mode=tree to use tree packing)"
                            .to_string(),
                    }),
                ));
            }
            respond_inspiring(&state.crs, &state.db, &query)
        }
        PackingMode::Tree => respond_one_packing(&state.crs, &state.db, &query),
    }
    .map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!("Query processing failed: {}", e),
            }),
        )
    })?;

    Ok(Json(QueryResponse {
        response,
        processing_time_ms: 0,
    }))
}

fn test_params() -> InspireParams {
    InspireParams {
        ring_dim: 256,
        q: 1152921504606830593,
        crt_moduli: vec![1152921504606830593],
        p: 65536,
        sigma: 6.4,
        gadget_base: 1 << 20,
        gadget_len: 3,
        security_level: inspire::params::SecurityLevel::Bits128,
    }
}

#[tokio::test]
async fn http_inspiring_requires_packing_keys() {
    let params = test_params();
    let d = params.ring_dim;

    let num_entries = d;
    let entry_size = 2; // 1 column per entry, values < 256

    let database: Vec<u8> = (0..num_entries)
        .flat_map(|i| {
            let low_byte = (i % 256) as u8;
            let high_byte = 0u8;
            vec![low_byte, high_byte]
        })
        .collect();

    let mut sampler = GaussianSampler::new(params.sigma);
    let (crs, encoded_db, rlwe_sk) = setup(&params, &database, entry_size, &mut sampler)
        .expect("setup should succeed");

    let target_index = 42u64;
    let (state, mut client_query) =
        query(&crs, target_index, &encoded_db.config, &rlwe_sk, &mut sampler)
            .expect("query should succeed");

    // Ensure we request InspiRING explicitly
    client_query.packing_mode = PackingMode::Inspiring;

    let app_state = Arc::new(AppState {
        crs: crs.clone(),
        db: encoded_db.clone(),
    });

    let app = Router::new().route("/query", post(handle_query)).with_state(app_state);

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind should succeed");
    let addr: SocketAddr = listener.local_addr().expect("local addr");

    let server_handle = tokio::spawn(async move {
        axum::serve(listener, app).await.expect("server should run");
    });

    let base_url = format!("http://{}", addr);
    let client = reqwest::Client::new();

    // Success path: packing keys included
    let ok_response = client
        .post(format!("{}/query", base_url))
        .json(&client_query)
        .send()
        .await
        .expect("request should succeed");

    assert!(ok_response.status().is_success());
    let ok_body: QueryResponse = ok_response
        .json()
        .await
        .expect("parse response");

    let extracted = extract_inspiring(&crs, &state, &ok_body.response, entry_size)
        .expect("extract should succeed");
    let expected_start = (target_index as usize) * entry_size;
    let expected = &database[expected_start..expected_start + entry_size];
    assert_eq!(extracted.as_slice(), expected);

    // Error path: missing packing keys
    let mut missing_keys_query = client_query.clone();
    missing_keys_query.inspiring_packing_keys = None;

    let err_response = client
        .post(format!("{}/query", base_url))
        .json(&missing_keys_query)
        .send()
        .await
        .expect("request should succeed");

    assert_eq!(err_response.status(), StatusCode::BAD_REQUEST);
    let err_body: ErrorResponse = err_response
        .json()
        .await
        .expect("parse error response");
    assert!(err_body
        .error
        .contains("InspiRING packing keys missing"));

    server_handle.abort();
}
