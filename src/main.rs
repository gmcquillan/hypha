use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Parser, Subcommand};
use hypha::capability::{token_id_hex, InviteConfig};
use hypha::node::NodeConfig;
use hypha::HyphaNode;

#[derive(Parser)]
#[command(name = "hypha", about = "Capability-based cooperation protocol")]
struct Cli {
    /// Data directory for keys and database
    #[arg(long, default_value = ".hypha")]
    data_dir: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Initialize a new node (generate keypair)
    Init,

    /// Start listening for incoming connections
    Listen {
        #[arg(long, default_value = "4433")]
        port: u16,
    },

    /// Create an invite link
    Invite {
        /// Comma-separated scopes to grant
        #[arg(long)]
        scopes: String,

        /// Maximum number of peers that can claim this invite
        #[arg(long, default_value = "1")]
        max_claims: u32,

        /// Connection hint (address:port)
        #[arg(long)]
        hint: String,

        /// Expiry in hours
        #[arg(long)]
        expires_hours: Option<u64>,
    },

    /// Claim an invite link
    Claim {
        /// The hypha:// invite link
        link: String,
    },

    /// Send a request to a peer
    Request {
        /// Peer public key (hex)
        #[arg(long)]
        peer: String,

        /// Scope for the request
        scope: String,

        /// Request body
        body: String,
    },

    /// List known peers
    Peers,

    /// Revoke a token
    Revoke {
        /// Token ID (hex)
        token_id: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();

    match cli.command {
        Command::Init => {
            let config = NodeConfig {
                data_dir: cli.data_dir.clone(),
                key_created_at: now_unix(),
            };
            let node = HyphaNode::open(config)?;
            println!("Node initialized.");
            println!("Public key: {}", hex_encode(node.public_key()));
            println!("Data dir: {}", cli.data_dir.display());
        }

        Command::Listen { port } => {
            let config = NodeConfig {
                data_dir: cli.data_dir,
                key_created_at: now_unix(),
            };
            let mut node = HyphaNode::open(config)?;
            let addr: SocketAddr = format!("0.0.0.0:{port}").parse()?;

            // Register an echo handler for testing
            node.on_request("echo", |req| async move {
                Ok(req.body.clone())
            })
            .await;

            node.listen(addr).await?;
            println!("Listening on {addr}");
            println!("Public key: {}", hex_encode(node.public_key()));

            // Keep running
            tokio::signal::ctrl_c().await?;
            println!("\nShutting down.");
        }

        Command::Invite {
            scopes,
            max_claims,
            hint,
            expires_hours,
        } => {
            let config = NodeConfig {
                data_dir: cli.data_dir,
                key_created_at: now_unix(),
            };
            let node = HyphaNode::open(config)?;

            let invite_config = InviteConfig {
                scopes: scopes.split(',').map(String::from).collect(),
                max_claims,
                expires_in: expires_hours.map(|h| std::time::Duration::from_secs(h * 3600)),
                connection_hints: vec![hint],
            };

            let token = node.create_invite(invite_config)?;
            let link = token.to_link()?;

            println!("Invite created.");
            println!("Token ID: {}", token_id_hex(&token.token_id));
            println!("Scopes: {:?}", token.scopes);
            println!("Max claims: {}", token.max_claims);
            println!("\nShare this link:\n{link}");
        }

        Command::Claim { link } => {
            let config = NodeConfig {
                data_dir: cli.data_dir,
                key_created_at: now_unix(),
            };
            let node = HyphaNode::open(config)?;

            println!("Claiming invite...");
            let peer = node.claim_invite(&link).await?;
            println!("Connected to peer: {}", hex_encode(peer.pubkey));
            println!("Granted scopes: {:?}", peer.scopes);
        }

        Command::Request { peer: _, scope: _, body: _ } => {
            println!("Request command not yet implemented for CLI (requires active connection)");
        }

        Command::Peers => {
            let config = NodeConfig {
                data_dir: cli.data_dir,
                key_created_at: now_unix(),
            };
            let node = HyphaNode::open(config)?;
            let peers = node.store().list_peers()?;

            if peers.is_empty() {
                println!("No known peers.");
            } else {
                for (pubkey, record) in peers {
                    println!(
                        "  {} — addr: {} last seen: {}",
                        hex_encode(&pubkey),
                        record.last_addr.as_deref().unwrap_or("unknown"),
                        record
                            .last_seen
                            .map(|t| t.to_string())
                            .unwrap_or_else(|| "never".into()),
                    );
                }
            }
        }

        Command::Revoke { token_id } => {
            let config = NodeConfig {
                data_dir: cli.data_dir,
                key_created_at: now_unix(),
            };
            let node = HyphaNode::open(config)?;
            let bytes = hex_decode(&token_id)?;
            node.revoke(&bytes)?;
            println!("Token {token_id} revoked.");
        }
    }

    Ok(())
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn hex_encode(bytes: impl AsRef<[u8]>) -> String {
    bytes
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn hex_decode(s: &str) -> anyhow::Result<Vec<u8>> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(Into::into))
        .collect()
}
