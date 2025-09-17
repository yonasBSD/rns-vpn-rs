//! Reticulum VPN client

use std::{fs, process};

use clap::Parser;
use ed25519_dalek;
use env_logger;
use log;
use pem;
use reticulum::identity::PrivateIdentity;
use reticulum::iface::udp::UdpInterface;
use reticulum::transport::{Transport, TransportConfig};
use tokio;
use x25519_dalek;

use rns_vpn;

const CONFIG_PATH: &str = "Config.toml";

/// Command line arguments
#[derive(Parser)]
#[command(name = "Reticulum VPN Client", version)]
pub struct Command {
  /// Reticulum UDP listen port number
  #[arg(short, long)]
  pub port: u16,
  /// Reticulum UDP forward link address
  #[arg(short, long)]
  pub forward: std::net::SocketAddr,
  /// [Optional] Reticulum private ID from name string
  #[arg(short, long)]
  pub id_string: Option<String>
}

#[tokio::main]
async fn main() {
  // parse command line args
  let cmd = Command::parse();
  // load config
  let config: rns_vpn::Config = {
    let s = fs::read_to_string(CONFIG_PATH).unwrap();
    toml::from_str(&s).unwrap()
  };
  // init logging
  env_logger::Builder::from_env(env_logger::Env::default()).init();
  log::info!("client start with port {} and forward IP {}", cmd.port, cmd.forward);
  // client
  let client = match rns_vpn::Client::new(config) {
    Ok(client) => client,
    Err(err) => match err {
      rns_vpn::CreateClientError::RiptunError(riptun::Error::Unix {
        source: nix::errno::Errno::EPERM
      }) => {
        log::error!("EPERM error creating VPN client: need to run with root permissions");
        process::exit(1)
      }
      _ => {
        log::error!("error creating VPN client: {:?}", err);
        process::exit(1)
      }
    }
  };
  // start reticulum
  log::info!("starting reticulum");
  let id = if let Some(name) = cmd.id_string {
    log::info!("using identity string to create reticulum private identity: {name:?}");
    PrivateIdentity::new_from_name(&name)
  } else {
    log::info!("loading reticulum private identity parameters");
    let private_key = {
      let path = std::env::var("RNS_VPN_PRIVKEY_PATH").map_err(|err|{
        log::error!("env variable RNS_VPN_PRIVKEY_PATH not found: {err:?}");
        process::exit(1)
      }).unwrap();
      log::info!("loading privkey: {path}");
      let pem_data = fs::read(&path).map_err(|err|{
        log::error!("failed to read privkey {path}: {err:?}");
        process::exit(1)
      }).unwrap();
      let pem = pem::parse(pem_data).map_err(|err|{
        log::error!("failed to parse privkey {path}: {err:?}");
        process::exit(1)
      }).unwrap();
      let pem_bytes: [u8; 32] = pem.contents()[pem.contents().len()-32..].try_into()
        .map_err(|err|{
          log::error!("invalid privkey bytes: {err:?}");
          process::exit(1)
        }).unwrap();
      x25519_dalek::StaticSecret::from(pem_bytes)
    };
    let sign_key = {
      use ed25519_dalek::pkcs8::DecodePrivateKey;
      let path = std::env::var("RNS_VPN_SIGNKEY_PATH").map_err(|err|{
        log::error!("env variable RNS_VPN_SIGNKEY_PATH not found: {err:?}");
        process::exit(1)
      }).unwrap();
      log::info!("loading signkey: {path}");
      ed25519_dalek::SigningKey::read_pkcs8_pem_file(&path).map_err(|err|{
        log::error!("failed to parse signkey {path}: {err:?}");
      }).unwrap()
    };
    PrivateIdentity::new(private_key, sign_key)
  };
  let transport = Transport::new(TransportConfig::new("server", &id, true));
  let _ = transport.iface_manager().lock().await.spawn(
    UdpInterface::new(format!("0.0.0.0:{}", cmd.port), Some(cmd.forward.to_string())),
    UdpInterface::spawn);
  // run
  client.run(transport, id).await;
  log::info!("server exit");
}
