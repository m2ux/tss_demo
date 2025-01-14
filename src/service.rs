use crate::error::Error;
use crate::protocol::discover_committee_members;
use crate::storage::KeyStorage;

/// Runs the application in signing-service mode
pub async fn run_service_mode(
    _server_addr: String,
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
