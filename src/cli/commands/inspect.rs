//! `kairox inspect` — read-only normalized SeaDrop state. Never broadcasts.

use alloy_primitives::Address;

use crate::chain::config::{EnvSource, ProcessEnv};
use crate::chain::registry::ChainRegistry;
use crate::cli::args::InspectArgs;
use crate::cli::context::{connect_read_client, resolve_chain};
use crate::cli::format::format_unix;
use crate::cli::gather;
use crate::execution::errors::KairoxError;
use crate::opensea::client::{OPENSEA_API_KEY_ENV, OpenSeaClient};
use crate::opensea::errors::OpenSeaError;

pub async fn run(args: InspectArgs) -> Result<(), KairoxError> {
    let registry = ChainRegistry::builtin();
    let resolved = resolve_chain(&registry, &args.chain_args)?;
    let client = connect_read_client(&resolved.info, args.chain_args.rpc_url.as_ref()).await?;

    println!(
        "Chain: {} (chain id {})",
        resolved.info.name, resolved.info.chain_id
    );
    println!("NFT contract: {}", args.collection);
    println!("SeaDrop contract: {}", resolved.seadrop_contract);
    println!();

    match gather::fetch_public_drop(&client, resolved.seadrop_contract, args.collection).await {
        Ok(public_drop) => {
            println!("Public stage:");
            println!("  mint price: {} wei", public_drop.mint_price);
            println!(
                "  start time: {} (unix {})",
                format_unix(public_drop.start_time),
                public_drop.start_time
            );
            println!(
                "  end time:   {} (unix {})",
                format_unix(public_drop.end_time),
                public_drop.end_time
            );
            println!(
                "  max per wallet: {}",
                public_drop.max_total_mintable_by_wallet
            );
            println!(
                "  fee: {} bps ({:.2}%)",
                public_drop.fee_bps,
                f64::from(public_drop.fee_bps) / 100.0
            );
            println!(
                "  restrict fee recipients: {}",
                public_drop.restrict_fee_recipients
            );
        }
        Err(e) => println!("Public stage: COULD NOT BE SAFELY DETERMINED ({e})"),
    }
    println!();

    match gather::fetch_allowed_fee_recipients(&client, resolved.seadrop_contract, args.collection)
        .await
    {
        Ok(allowed) => println!(
            "Allowed fee recipients: {}",
            crate::cli::format::format_addr_list(&allowed)
        ),
        Err(e) => println!("Allowed fee recipients: COULD NOT BE SAFELY DETERMINED ({e})"),
    }
    println!();

    let mint_stats_query_address = args.wallet.unwrap_or(Address::ZERO);
    match gather::fetch_mint_stats(&client, args.collection, mint_stats_query_address).await {
        Ok(stats) => {
            println!("Supply:");
            println!("  current total supply: {}", stats.current_total_supply);
            println!("  max supply: {}", stats.max_supply);
            match args.wallet {
                Some(wallet) => println!(
                    "  wallet {wallet} already minted: {}",
                    stats.minter_num_minted
                ),
                None => println!(
                    "  wallet already-minted: not shown (pass --wallet to check a specific address)"
                ),
            }
        }
        Err(e) => println!("Supply: COULD NOT BE SAFELY DETERMINED ({e})"),
    }

    if let Some(slug) = &args.slug {
        println!();
        println!("=================================================");
        println!(" OPENSEA API METADATA (off-chain, informational only)");
        println!(" Never treated as stronger than the on-chain verified state above.");
        println!("=================================================");
        match ProcessEnv.get(OPENSEA_API_KEY_ENV) {
            Ok(Some(api_key)) => {
                let opensea = OpenSeaClient::new_http(api_key, std::time::Duration::from_secs(10));
                match opensea.get_drop_details(slug).await {
                    Ok(details) => {
                        println!("collection_slug:  {}", details.collection_slug);
                        println!("chain:            {}", details.chain);
                        println!("contract_address: {}", details.contract_address);
                        println!("drop_type:        {}", details.drop_type);
                        println!("is_minting:       {}", details.is_minting);
                        println!("stages:           {}", details.stages.len());
                        for stage in &details.stages {
                            println!(
                                "  - {} ({}): start={} end={} max_per_wallet={}",
                                stage.stage_type,
                                stage.label.as_deref().unwrap_or("(unlabeled)"),
                                stage.start_time,
                                stage.end_time,
                                stage.max_per_wallet
                            );
                        }
                    }
                    Err(e) => println!("OpenSea drop details: COULD NOT BE FETCHED ({e})"),
                }
            }
            Ok(None) | Err(_) => {
                println!(
                    "OpenSea drop details: NOT FETCHED ({})",
                    OpenSeaError::ApiKeyMissing
                );
            }
        }
    }

    Ok(())
}
