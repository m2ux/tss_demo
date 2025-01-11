use crate::error::Error;
use crate::network::WsDelivery;
use crate::protocol::discover_committee_members;
use crate::storage::KeyStorage;
use cggmp21::keygen::ThresholdMsg;
use cggmp21::security_level::SecurityLevel128;
use cggmp21::supported_curves::Secp256k1;
use sha2::Sha256;

/// Runs the application in signing-service mode
pub async fn run_service_mode(
    _delivery: WsDelivery<ThresholdMsg<Secp256k1, SecurityLevel128, Sha256>>,
    _storage: KeyStorage,
    _party_id: u16,
    message: String,
) -> Result<(), Error> {
    println!("Starting signing process for message: {}", message);

    // Discover available committee members
    let committee = discover_committee_members().await?;
    println!("Found {} committee members", committee.len());

    // Check if we have enough committee members for threshold
    if committee.len() < 3 {
        return Err(Error::Config(
            "Not enough committee members available (minimum 3 required)".into(),
        ));
    }

    //TODO

    // Display the resulting signature
    println!("Signature generated successfully:");

    Ok(())
}
