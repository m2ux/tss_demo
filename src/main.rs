mod network;
mod storage;
mod error;
mod server;

use clap::Parser;
use error::Error;
use cggmp21::{
    supported_curves::Secp256k1,
    ExecutionId,
    keygen::ThresholdMsg,
    security_level::SecurityLevel128,
};
use network::WsDelivery;
use storage::KeyStorage;
use sha2::Sha256;
use round_based::MpcParty;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Message to be signed
    #[arg(short, long)]
    message: String,

    /// Party IDs for the signing committee (comma-separated)
    #[arg(short, long)]
    signers: String,

    /// Local party ID
    #[arg(short, long)]
    party_id: u16,

    /// WebSocket server address
    #[arg(short, long)]
    server: String,
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let args = Args::parse();

    // Parse signing committee
    let committee: Vec<u16> = args.signers
        .split(',')
        .map(|s| s.trim().parse::<u16>())
        .collect::<Result<Vec<u16>, _>>()
        .map_err(|_| Error::Config("Invalid committee specification".into()))?;

    if committee.len() < 3 {
        return Err(Error::Config("At least 3 signers are required".into()));
    }

    // Initialize storage
    let storage = KeyStorage::new(
        "keys",
        "a very secret key that should be properly secured",
    )?;

    // Initialize network connection
    type Msg = ThresholdMsg<Secp256k1, SecurityLevel128, Sha256>;
    let delivery = WsDelivery::<Msg>::connect(&args.server, args.party_id).await?;

    // Start key generation
    println!("Starting key generation protocol...");
    let keygen_eid = ExecutionId::new(b"keygen-1");

    let incomplete_key_share = cggmp21::keygen::<Secp256k1>(keygen_eid, args.party_id, committee.len() as u16)
        .set_threshold(3)
        .enforce_reliable_broadcast(true)
        .start(&mut rand_core::OsRng, MpcParty::connected(delivery))
        .await?;

    // Store incomplete key share
    storage.save("incomplete_key_share", &incomplete_key_share)?;

    println!("Key generation completed successfully!");
    println!("Incomplete key share has been securely stored.");

    Ok(())
}