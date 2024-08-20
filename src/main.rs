// Copyright © Aptos Foundation
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Error, Context, Result};
use aptos_sdk::{
    coin_client::CoinClient,
    rest_client::{
      Client, FaucetClient,
      aptos_api_types::{U64, ViewRequest, EntryFunctionId, VersionedEvent}
    },
    types::{LocalAccount, transaction::authenticator::AuthenticationKey},
    transaction_builder::TransactionBuilder,
    move_types::{
      ident_str,
      language_storage::{ModuleId, TypeTag},
    },
    crypto::{ed25519::{ Ed25519PrivateKey, Ed25519PublicKey, Ed25519Signature, PublicKey, PrivateKey}, ValidCryptoMaterialStringExt},
    transaction_builder::TransactionFactory,
    types::{
      account_address::AccountAddress,
      transaction::{
        EntryFunction, Script, SignedTransaction, TransactionArgument, TransactionPayload,
      }
    }
};

use once_cell::sync::Lazy;
use std::str::FromStr;
use url::Url;
use tiny_keccak::{Hasher, Sha3};
use std::collections::BTreeMap;
use serde::{Serialize, Deserialize};

// :!:>section_1c
static NODE_URL: Lazy<Url> = Lazy::new(|| {
    Url::from_str(
        std::env::var("APTOS_NODE_URL")
            .as_ref()
            .map(|s| s.as_str())
            .unwrap_or("https://fullnode.testnet.aptoslabs.com"),
    )
    .unwrap()
});

static FAUCET_URL: Lazy<Url> = Lazy::new(|| {
    Url::from_str(
        std::env::var("APTOS_FAUCET_URL")
            .as_ref()
            .map(|s| s.as_str())
            .unwrap_or("https://faucet.testnet.aptoslabs.com"),
    )
    .unwrap()
});
// <:!:section_1c

#[tokio::main]
async fn main() -> Result<()> {
    // :!:>section_1a
    let rest_client = Client::new(NODE_URL.clone());
    let faucet_client = FaucetClient::new(FAUCET_URL.clone(), NODE_URL.clone()); // <:!:section_1a

    // :!:>section_1b
    let coin_client = CoinClient::new(&rest_client); // <:!:section_1b

    // Create two accounts locally, Alice and Bob.
    // :!:>section_2
    let mut alice = LocalAccount::generate(&mut rand::rngs::OsRng);
    let bob = LocalAccount::generate(&mut rand::rngs::OsRng);

    // https://fullnode.devnet.aptoslabs.com/v1/accounts/
  /*
    let contract_address = AccountAddress::from_hex_literal("0x60fdd95a3d802f33a5e8623c50b1cdc4967c28bed42ba861e592f54786d186e3")?;
    let events = rest_client.get_account_events(
      contract_address,
      "0x60fdd95a3d802f33a5e8623c50b1cdc4967c28bed42ba861e592f54786d186e3::mailbox::MailBoxState",
      "dispatch_events",
      None,
      Some(10000)
    ).await?
    .into_inner();
  // println!("events: {:?}", events);

    let start_block = rest_client.get_block_by_height(1104065, false)
        .await?
        .into_inner();
    
    let end_block = rest_client.get_block_by_height(1881084, false)
        .await?
        .into_inner();
    
    let start_version = start_block.first_version;
    let end_version = end_block.last_version;
    
    println!("start_version: {:?}", start_version);
    println!("end_version: {:?}", end_version);

    let new_events: Vec<VersionedEvent> = events
      .into_iter()
      .filter(|e| 
        e.version.0 > start_version.0 
        && e.version.0 <= end_version.0
      )
      .collect();

    println!("new_events: {:?}", new_events);

    for evt in new_events {
      let msg_data = serde_json::from_str::<DispatchEventData>(&evt.data.to_string()).unwrap();
      println!("msg_data: {:?}", msg_data);
    }

 */

  let message_bytes: Vec<u8> = vec![0, 0, 0, 0, 1, 0, 0, 0, 97, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 118, 39, 102, 73, 149, 116, 182, 137, 233, 13, 239, 188, 217, 2, 219, 146, 227, 10, 13, 161, 0, 0, 56, 66, 8, 11, 36, 92, 1, 133, 94, 239, 8, 112, 187, 246, 47, 176, 170, 51, 185, 117, 145, 43, 87, 210, 246, 95, 69, 152, 107, 234, 121, 207, 129, 42, 72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100, 33];
  let view_response = rest_client.view(
    &ViewRequest {
      function: EntryFunctionId::from_str(
        &format!(
          "{}::multisig_ism::validators_and_threshold", 
          "0xc0c7902ff2cbd7c32b76b389f07738c61b90f8335be1fe0b74e2e60e4a362d33"
        )
      ).unwrap(),
      type_arguments: vec![],
      arguments: vec![
        serde_json::json!(hex::encode(message_bytes))
      ]
    },
    Option::None
  )
  .await?;
  
  println!("view_response :{:?}", view_response.inner()[0]);

  let validators = serde_json::from_str::<Vec<String>>(&view_response.inner()[0].to_string()).unwrap();
  let threshold = serde_json::from_str::<String>(&view_response.inner()[1].to_string()).unwrap().parse::<u64>().unwrap();
  println!("view_result :{:?} {:?}", validators, threshold);

  let view_response = rest_client.view(
    &ViewRequest {
      function: EntryFunctionId::from_str(
        &format!(
          "{}::mailbox::get_default_ism", 
          "0x0b1613d9a5edd5cfe9d21c092954952adf8384adf87a8c7e1d42bb9da49ec85f"
        )
      ).unwrap(),
      type_arguments: vec![],
      arguments: vec![]
    },
    Option::None
  )
  .await?;
  
  println!("view_response :{:?}", view_response.inner());
  let ism_address = serde_json::from_str::<String>(&view_response.inner()[0].to_string()).unwrap();

  println!("view_result :{:?}", format!("{:0>64}", ism_address.trim_start_matches("0x")));
  println!("hex::decode(ism_address) :{:?}", hex::decode(ism_address));
  
        let signer_priv_key = Ed25519PrivateKey::try_from(
          hex::decode("_").unwrap().as_ref()
        ).unwrap();
        let signer_address = AuthenticationKey::ed25519(&Ed25519PublicKey::from(&signer_priv_key)).derived_address();

        println!("address = {}", signer_address.to_hex());


  println!("path_prefix_string = {}", rest_client.path_prefix_string());

  let addy = "d1eaef049ac77e63f2ffefae43e14c1a73700f25cde849b6614dc3f3580123fc";
  //"e6738b6B8910EF3f3fc1AEAc4e92B065607D8E5f";
  // [230,115,139,107,137,16,239,63,63,193,174,172,78,146,176,101,96,125,142,95]

  //b2586f8d1347b988157b9e7aaea24d19064dfb596835145db1f93ff931948732
  // [178,88,111,141,19,71,185,136,21,123,158,122,174,162,77,25,6,77,251,89,104,53,20,93,177,249,63,249,49,148,135,50]

  //d1eaef049ac77e63f2ffefae43e14c1a73700f25cde849b6614dc3f3580123fc
//  [209,234,239,4,154,199,126,99,242,255,239,174,67,225,76,26,115,112,15,37,205,232,73,182,97,77,195,243,88,1,35,252]
  println!("res: {:?}",hex::decode(addy).unwrap());
  Ok(())
}

#[derive(Serialize,Deserialize, Debug)]
struct DispatchEventData {
  dest_domain: u64,
  message: String,
  message_id: String,
  recipient: String,
  sender: String
}

#[derive(Serialize, Deserialize, Debug)]
struct ValidatorsAndThresholdMoveValue {
  validators: serde_json::Value,
  threshold: String,
}
