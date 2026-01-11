//! inspire-server: PIR server with HTTP API
//!
//! Serves PIR queries over HTTP, loading preprocessed data from inspire-setup.

use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use clap::Parser;
use eyre::{Context, Result};
use serde::{Deserialize, Serialize};
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

use inspire_pir::pir::{
    respond_inspiring, respond_mmap_one_packing, respond_one_packing, respond_seeded_packed,
    ClientQuery, EncodedDatabase, InspireCrs, MmapDatabase, SeededClientQuery, ServerResponse,
};

#[derive(Parser)]
#[command(name = "inspire-server")]
#[command(about = "InsPIRe PIR server")]
#[command(version)]
struct Args {
    /// Path to preprocessed data directory
    #[arg(long, default_value = "inspire_data")]
    data_dir: PathBuf,

    /// Server bind address
    #[arg(long, default_value = "0.0.0.0:3000")]
    bind: String,

    /// Use memory-mapped shards (for large databases)
    #[arg(long)]
    mmap: bool,
}

enum DatabaseMode {
    InMemory(EncodedDatabase),
    Mmap(MmapDatabase),
}

struct AppState {
    crs: InspireCrs,
    db: DatabaseMode,
    metadata: ServerMetadata,
}

#[derive(Clone, Serialize, Deserialize)]
struct ServerMetadata {
    version: String,
    ring_dim: usize,
    modulus: String,
    plaintext_modulus: u64,
    entry_count: u64,
    shard_count: usize,
}

#[derive(Serialize)]
struct HealthResponse {
    status: String,
    version: String,
}

#[derive(Serialize)]
struct ParamsResponse {
    version: String,
    ring_dim: usize,
    modulus: String,
    plaintext_modulus: u64,
    gadget_base: u64,
    gadget_len: usize,
    entry_count: u64,
    shard_count: usize,
    crs_a_vectors_count: usize,
}

#[derive(Serialize)]
struct QueryResponse {
    response: ServerResponse,
    processing_time_ms: u64,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

async fn health_check() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    })
}

async fn get_params(State(state): State<Arc<AppState>>) -> Json<ParamsResponse> {
    Json(ParamsResponse {
        version: state.metadata.version.clone(),
        ring_dim: state.crs.params.ring_dim,
        modulus: state.crs.params.q.to_string(),
        plaintext_modulus: state.crs.params.p,
        gadget_base: state.crs.params.gadget_base,
        gadget_len: state.crs.params.gadget_len,
        entry_count: state.metadata.entry_count,
        shard_count: state.metadata.shard_count,
        crs_a_vectors_count: state.crs.crs_a_vectors.len(),
    })
}

async fn handle_query(
    State(state): State<Arc<AppState>>,
    Json(query): Json<ClientQuery>,
) -> Result<Json<QueryResponse>, (StatusCode, Json<ErrorResponse>)> {
    let start = Instant::now();

    // Use InspiRING if packing keys available (~35x faster), otherwise tree packing
    let response = match &state.db {
        DatabaseMode::InMemory(encoded_db) => {
            if query.inspiring_packing_keys.is_some() {
                respond_inspiring(&state.crs, encoded_db, &query)
            } else {
                respond_one_packing(&state.crs, encoded_db, &query)
            }
        }
        DatabaseMode::Mmap(mmap_db) => {
            // TODO: Add respond_mmap_inspiring when needed
            respond_mmap_one_packing(&state.crs, mmap_db, &query)
        }
    }
    .map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!("Query processing failed: {}", e),
            }),
        )
    })?;

    let processing_time_ms = start.elapsed().as_millis() as u64;

    Ok(Json(QueryResponse {
        response,
        processing_time_ms,
    }))
}

async fn handle_seeded_query(
    State(state): State<Arc<AppState>>,
    Json(query): Json<SeededClientQuery>,
) -> Result<Json<QueryResponse>, (StatusCode, Json<ErrorResponse>)> {
    let start = Instant::now();

    let response = match &state.db {
        DatabaseMode::InMemory(encoded_db) => respond_seeded_packed(&state.crs, encoded_db, &query),
        DatabaseMode::Mmap(mmap_db) => {
            let expanded = query.expand();
            respond_mmap_one_packing(&state.crs, mmap_db, &expanded)
        }
    }
    .map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!("Seeded query processing failed: {}", e),
            }),
        )
    })?;

    let processing_time_ms = start.elapsed().as_millis() as u64;

    Ok(Json(QueryResponse {
        response,
        processing_time_ms,
    }))
}

async fn get_crs(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    Json(state.crs.clone())
}

#[tokio::main]
async fn main() -> Result<()> {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .with_target(false)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    let args = Args::parse();

    info!("InsPIRe PIR Server");
    info!("Data directory: {}", args.data_dir.display());
    info!("Bind address: {}", args.bind);

    info!("Loading CRS...");
    let load_start = Instant::now();

    let crs_path = args.data_dir.join("crs.json");
    let crs_file = File::open(&crs_path)
        .with_context(|| format!("Failed to open CRS file: {}", crs_path.display()))?;
    let reader = BufReader::new(crs_file);
    let crs: InspireCrs =
        serde_json::from_reader(reader).with_context(|| "Failed to deserialize CRS")?;

    info!("CRS loaded: ring_dim={}", crs.ring_dim());

    let metadata = load_metadata(&args.data_dir)?;

    let db = if args.mmap {
        info!("Loading database in mmap mode...");
        let shards_dir = args.data_dir.join("shards");
        if !shards_dir.exists() {
            return Err(eyre::eyre!(
                "Shards directory not found: {}. Run setup with --binary-output first.",
                shards_dir.display()
            ));
        }

        let shard_config = inspire_pir::params::ShardConfig {
            shard_size_bytes: (crs.ring_dim() as u64) * 32,
            entry_size_bytes: 32,
            total_entries: metadata.entry_count,
        };

        let mmap_db = MmapDatabase::open(&shards_dir, shard_config)
            .with_context(|| "Failed to open mmap database")?;

        info!("Mmap database loaded: {} shards", mmap_db.num_shards());
        DatabaseMode::Mmap(mmap_db)
    } else {
        info!("Loading encoded database into memory...");
        let db_path = args.data_dir.join("encoded_db.json");
        let db_file = File::open(&db_path)
            .with_context(|| format!("Failed to open database file: {}", db_path.display()))?;
        let reader = BufReader::new(db_file);
        let encoded_db: EncodedDatabase = serde_json::from_reader(reader)
            .with_context(|| "Failed to deserialize encoded database")?;

        info!(
            "Encoded database loaded: {} shards",
            encoded_db.shards.len()
        );
        DatabaseMode::InMemory(encoded_db)
    };

    info!("Load time: {:.2?}", load_start.elapsed());

    let state = Arc::new(AppState { crs, db, metadata });

    let app = Router::new()
        .route("/health", get(health_check))
        .route("/params", get(get_params))
        .route("/crs", get(get_crs))
        .route("/query", post(handle_query))
        .route("/query_seeded", post(handle_seeded_query))
        .with_state(state);

    info!("Starting server on {}", args.bind);
    let listener = tokio::net::TcpListener::bind(&args.bind).await?;

    println!();
    println!("=== InsPIRe PIR Server Running ===");
    println!("Listening on: http://{}", args.bind);
    println!();
    println!("Endpoints:");
    println!("  GET  /health  - Health check");
    println!("  GET  /params  - Get public parameters");
    println!("  GET  /crs     - Get full CRS (large)");
    println!("  POST /query   - Process PIR query");
    println!("  POST /query_seeded - Process seeded PIR query (TwoPacking)");
    println!();

    axum::serve(listener, app).await?;

    Ok(())
}

fn load_metadata(data_dir: &PathBuf) -> Result<ServerMetadata> {
    let meta_path = data_dir.join("metadata.json");

    if meta_path.exists() {
        let meta_file = File::open(&meta_path)?;
        let reader = BufReader::new(meta_file);

        #[derive(Deserialize)]
        struct FileMetadata {
            version: String,
            ring_dim: usize,
            modulus: String,
            plaintext_modulus: u64,
            entry_count: u64,
            shard_count: usize,
        }

        let file_meta: FileMetadata = serde_json::from_reader(reader)?;

        Ok(ServerMetadata {
            version: file_meta.version,
            ring_dim: file_meta.ring_dim,
            modulus: file_meta.modulus,
            plaintext_modulus: file_meta.plaintext_modulus,
            entry_count: file_meta.entry_count,
            shard_count: file_meta.shard_count,
        })
    } else {
        info!("No metadata.json found, using defaults");
        Ok(ServerMetadata {
            version: "1.0.0".to_string(),
            ring_dim: 2048,
            modulus: "0".to_string(),
            plaintext_modulus: 65536,
            entry_count: 0,
            shard_count: 0,
        })
    }
}
