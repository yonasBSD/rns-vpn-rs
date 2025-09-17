use std::collections::BTreeMap;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use ipnet::IpNet;
use log;
use reticulum::destination::DestinationName;
use reticulum::destination::link::{LinkEvent, LinkId};
use reticulum::hash::AddressHash;
use reticulum::identity::PrivateIdentity;
use reticulum::transport::Transport;

use riptun::TokioTun;

// TODO: config?
const TUN_NQUEUES : usize = 1;
const MTU: usize = 1500;

#[derive(Deserialize, Serialize)]
pub struct Config {
  pub vpn_ip: IpNet,
  /// Map of (IP, destination)
  // TODO: deserialize AddressHash
  pub peers: BTreeMap<IpNet, String>
}

pub struct Client {
  config: Config,
  tun: Tun
}

#[derive(Debug)]
pub enum CreateClientError {
  ConfigError(String),
  RiptunError(riptun::Error),
  IpAddBroadcastError(std::io::Error),
  IpLinkUpError(std::io::Error),
  IpRouteAddError(std::io::Error),
  IptablesError(std::io::Error)
}

struct Tun {
  tun: TokioTun,
  read_buf: tokio::sync::Mutex<[u8; MTU]>
}

impl Client {
  pub fn new(config: Config) -> Result<Self, CreateClientError> {
    if config.peers.contains_key(&config.vpn_ip) {
      log::error!("configured VPN IP ({}) conflicts with peer IPs: {:?}",
        config.vpn_ip, config.peers);
      return Err(CreateClientError::ConfigError(
        "configured VPN IP exists in peer IPs".to_owned()))
    }
    let tun = Tun::new(config.vpn_ip)?;
    Ok(Client { config, tun })
  }

  pub async fn run(&self, mut transport: Transport, id: PrivateIdentity) {
    let in_destination = transport
      .add_destination(id, DestinationName::new("rns_vpn", "client")).await;
    let in_destination_hash = in_destination.lock().await.desc.address_hash;
    log::info!("created in destination: {}", in_destination_hash);
    // send announces
    let announce_loop = async || loop {
      transport.send_announce(&in_destination, None).await;
      tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    };
    let link_id: Arc<tokio::sync::Mutex<Option<LinkId>>> = Arc::new(tokio::sync::Mutex::new(None));
    // tun loop
    let tun_loop = async || while let Ok(bytes) = self.tun.read().await {
      log::trace!("got tun bytes ({})", bytes.len());
      let link_id = link_id.lock().await;
      if let Some(link_id) = link_id.as_ref() {
        log::trace!("sending on link ({})", link_id);
        let link = transport.find_in_link(link_id).await.unwrap();
        let link = link.lock().await;
        let packet = link.data_packet(&bytes).unwrap();
        transport.send_packet(packet).await;
      }
    };
    // upstream link data
    let link_loop = async || {
      let mut peer_map = BTreeMap::new();
      for (ip, dest) in self.config.peers.iter() {
        let dest = match AddressHash::new_from_hex_string(dest.as_str()) {
          Ok(dest) => dest,
          Err(err) => {
            log::error!("error parsing peer destination hash: {err:?}");
            return
          }
        };
        assert!(peer_map.insert(*ip, dest).is_none());
      }
      let mut in_link_events = transport.in_link_events();
      while let Ok(link_event) = in_link_events.recv().await {
        match link_event.event {
          LinkEvent::Data(payload) => if link_event.address_hash == in_destination_hash {
            log::trace!("link {} payload ({})", link_event.id, payload.len());
            match self.tun.send(payload.as_slice()).await {
              Ok(n) => log::trace!("tun sent {n} bytes"),
              Err(err) => {
                log::error!("tun error sending bytes: {err:?}");
                break
              }
            }
          }
          LinkEvent::Activated => if link_event.address_hash == in_destination_hash {
            log::debug!("link activated {}", link_event.id);
            let mut link_id = link_id.lock().await;
            *link_id = Some(link_event.id);
          }
          LinkEvent::Closed => if link_event.address_hash == in_destination_hash {
            log::debug!("link closed {}", link_event.id)
          }
        }
      }
    };
    tokio::select!{
      _ = announce_loop() => log::info!("announce loop exited: shutting down"),
      _ = tun_loop() => log::info!("tun loop exited: shutting down"),
      _ = link_loop() => log::info!("link loop exited: shutting down"),
      _ = tokio::signal::ctrl_c() => log::info!("got ctrl-c: shutting down")
    }
  }
}

impl Tun {
  pub fn new(ip: IpNet) -> Result<Self, CreateClientError> {
    log::debug!("creating tun device");
    let ip: IpNet = ip.into();
    let tun = TokioTun::new("rip%d", TUN_NQUEUES).map_err(CreateClientError::RiptunError)?;
    log::debug!("created tun device: {}", tun.name());
    log::debug!("adding broadcast ip addr: {}", ip);
    let output = std::process::Command::new("ip")
      .arg("addr")
      .arg("add")
      .arg(ip.to_string())
      .arg("brd")
      .arg(ip.addr().to_string())
      .arg("dev")
      .arg(tun.name())
      .output()
      .map_err(CreateClientError::IpAddBroadcastError)?;
    if !output.status.success() {
      return Err(CreateClientError::IpAddBroadcastError(
        std::io::Error::other(format!("ip addr add command failed ({:?})",
          output.status.code())).into()));
    }
    log::debug!("{} setting link up", tun.name());
    let output = std::process::Command::new("ip")
      .arg("link")
      .arg("set")
      .arg("dev")
      .arg(tun.name())
      .arg("up")
      .output()
      .map_err(CreateClientError::IpLinkUpError)?;
    if !output.status.success() {
      return Err(CreateClientError::IpLinkUpError(
        std::io::Error::other(format!("ip link set command failed ({:?})", output.status.code()))))
    }
    let adapter = Tun {
      tun, read_buf: tokio::sync::Mutex::new([0x0; MTU])
    };
    Ok(adapter)
  }

  #[allow(dead_code)]
  pub fn tun(&self) -> &TokioTun {
    &self.tun
  }

  // TODO: can we return a lock of &[u8] to avoid creating vec?
  pub async fn read(&self) -> Result<Vec<u8>, std::io::Error> {
    let mut buf = self.read_buf.lock().await;
    let nbytes = self.tun.recv(&mut buf[..]).await?;
    Ok(buf[..nbytes].to_vec())
  }

  pub async fn send(&self, datagram: &[u8]) -> Result<usize, std::io::Error> {
    self.tun.send(datagram).await
  }
}
