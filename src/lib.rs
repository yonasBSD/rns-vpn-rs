use std::collections::BTreeMap;
use std::convert::TryInto;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time;

use cidr;
use ed25519_dalek::{SIGNATURE_LENGTH, Signature, VerifyingKey};
use etherparse;
use ipnet::IpNet;
use log;
use rand_core::{OsRng, RngCore};
use riptun::TokioTun;
use serde::{Deserialize, Serialize};
use tokio;
use tokio::sync::Mutex;

use reticulum::destination::{DestinationName, SingleInputDestination};
use reticulum::destination::link::{LinkEvent, LinkId};
use reticulum::hash::{ADDRESS_HASH_SIZE, AddressHash};
use reticulum::identity::PrivateIdentity;
use reticulum::transport::Transport;

// TODO: config?
const TUN_NQUEUES : usize = 1;
const MTU: usize = 1500;

/// Indicates message is a peer authentication payload
const PEER_AUTH_BYTE: u8 = 0xFF;
const AUTH_NONCE_BYTES: usize = 10;
const SIG_BUFFER_SIZE: usize = ADDRESS_HASH_SIZE + AUTH_NONCE_BYTES;
const AUTH_SIZE: usize = ADDRESS_HASH_SIZE + SIGNATURE_LENGTH;
/// If in-link is older than this timeout without having been identified it should be
/// closed
const IN_LINK_AUTH_TIMEOUT: time::Duration = time::Duration::from_secs(5);

const fn default_announce_freq_secs() -> u32 { 3 }

#[derive(Deserialize, Serialize)]
pub struct Config {
  pub network: cidr::Ipv4Cidr,
  /// List of peer destination hashes
  pub peers: Vec<String>,
  #[serde(default = "default_announce_freq_secs")]
  pub announce_freq_secs: u32,
  /// Add to the peer list any peers opening an in-link for the local input destination
  #[serde(default)]
  pub allow_all: bool
}

pub struct Client {
  config: Config,
  transport: Arc<Mutex<Transport>>,
  in_destination: Arc<Mutex<SingleInputDestination>>,
  peer_map: Arc<Mutex<BTreeMap<IpAddr, Peer>>>,
  in_link_auths: Arc<Mutex<BTreeMap<LinkId, InLinkAuth>>>,
  tun: Arc<Tun>,
  run_handle: Option<(tokio::task::JoinHandle<()>, tokio::sync::watch::Sender<()>)>
}

#[derive(Debug)]
pub enum ClientError {
  ConfigError(String),
  RiptunError(riptun::Error),
  IpAddBroadcastError(std::io::Error),
  IpLinkUpError(std::io::Error),
  IpRouteAddError(std::io::Error),
  IptablesError(std::io::Error)
}

#[derive(Debug)]
pub enum PeerAddError {
  /// Attempt to add peer that already exists
  AlreadyExists,
  /// Attempted to add a peer that maps to the same IP as an existing peer
  IpConflicts(AddressHash, IpAddr)
}

#[derive(Debug)]
pub enum PeerRemoveError {
  /// Peer was not found
  NotFound
}

/// Peer information returned from `client.peer_list()`
#[derive(Clone)]
pub struct PeerInfo {
  pub dest: AddressHash,
  pub ip_addr: IpAddr,
  pub in_link_id: Option<LinkId>,
  pub out_link_id: Option<LinkId>
}

#[derive(Clone)]
struct Peer {
  dest: AddressHash,
  verify_key: Option<VerifyingKey>,
  in_link_id: Option<LinkId>,
  out_link_id: Option<LinkId>,
  /// Sent signed auth payload on out-link after receiving nonce from peer
  sent_auth: bool,
  /// If we have not yet received a peers announce we need to wait until it is received
  /// so we can validate the signature
  received_auth_payload: Option<[u8; AUTH_SIZE]>,
}

#[derive(Debug)]
#[allow(dead_code)]
enum PeerAuthError {
  MissingInLinkAuth(LinkId),
  InLinkAlreadyAuthorized(LinkId, AddressHash),
  InvalidSignature(LinkId, AddressHash),
  InvalidPayload(LinkId)
}

struct InLinkAuth {
  /// Time at which the link was opened
  pub link_open_ts: time::Instant,
  pub sent_nonce: [u8; AUTH_NONCE_BYTES],
  /// When this is present it indicates that the peer has succesfully identified itself
  /// on this in-link
  pub authorized_peer: Option<AddressHash>,
}

struct Tun {
  tun: TokioTun,
  read_buf: Mutex<[u8; MTU]>
}

impl Client {
  /// Initialize and run client on background tasks
  pub async fn run(config: Config, transport: Arc<Mutex<Transport>>, id: PrivateIdentity)
    -> Result<Self, ClientError>
  {
    let transport_clone = transport.clone();
    let mut client = Client::new(config, transport_clone.clone(), id).await?;
    let in_destination_hash = client.in_destination.lock().await.desc.address_hash;
    // send announces: also clean up in-links that have timed out
    let transport = transport_clone.clone();
    let announce_freq_secs = client.config.announce_freq_secs as u64;
    let in_link_auths = client.in_link_auths.clone();
    let in_destination = client.in_destination.clone();
    let announce_send_loop = async move || {
      let mut close_in_links = vec![];
      loop {
        transport.lock().await.send_announce(&in_destination, None).await;
        // close any in-links that have not authorized within the timeout
        let now = time::Instant::now();
        for (id, auth) in in_link_auths.lock().await.iter() {
          let age = now - auth.link_open_ts;
          let close = auth.authorized_peer.is_none() && age >= IN_LINK_AUTH_TIMEOUT;
          if close {
            log::warn!("in-link {id} timed out waiting for auth ({:?}), closing link",
              age);
            close_in_links.push(*id);
          }
        }
        for in_link_id in close_in_links.drain(..) {
          let transport = transport.lock().await;
          if let Some(link) = transport.find_in_link(&in_link_id).await.clone() {
            drop(transport);
            log::debug!("closing in-link {}", in_link_id);
            link.lock().await.close();
            // LinkEvent::Closed handling will take care of cleaning up
          } else {
            log::warn!("could not find in-link {}", in_link_id);
            debug_assert!(false, "could not find in-link {}", in_link_id);
          }
        }
        tokio::time::sleep(time::Duration::from_secs(announce_freq_secs)).await;
      }
    };
    // set up links: when an announce is received for a peer in the peer list, initiate
    // an outgoing link
    let transport = transport_clone.clone();
    let peer_map = client.peer_map.clone();
    let in_link_auths = client.in_link_auths.clone();
    let announce_recv_loop = async move || {
      let mut announce_recv = transport.lock().await.recv_announces().await;
      while let Ok(announce) = announce_recv.recv().await {
        let destination = announce.destination.lock().await;
        // look up destination in peers
        // TODO: constant time peer lookup?
        for peer in peer_map.lock().await.values_mut() {
          if destination.desc.address_hash == peer.dest {
            if peer.out_link_id.is_none() {
              let verify_key = destination.desc.identity.verifying_key;
              peer.verify_key = Some(verify_key);
              let link = transport.lock().await.link(destination.desc).await;
              peer.out_link_id = Some(link.lock().await.id().clone());
              log::debug!("requested out-link {} for peer {}",
                peer.out_link_id.as_ref().unwrap(), peer.dest);
              // if the peer has received an auth payload we can now validate it
              if let Some(auth_payload) = peer.received_auth_payload {
                if let Some(in_link_id) = peer.in_link_id {
                  if let Err(err) = peer_auth(
                    in_link_auths.clone(), in_link_id, peer, auth_payload.as_slice()
                  ).await {
                    log::error!("peer auth error: {err:?}");
                    // close the link
                    let transport = transport.lock().await;
                    if let Some(link) = transport.find_in_link(&in_link_id).await.clone() {
                      drop(transport);
                      log::warn!("closing in-link {}", in_link_id);
                      link.lock().await.close();
                      // LinkEvent::Closed handling will take care of cleaning up
                    } else {
                      log::warn!("could not find in-link {}", in_link_id);
                      debug_assert!(false, "could not find in-link {}", in_link_id);
                    }
                  }
                }
              }
            }
            break
          }
        }
      }
    };
    // out-links: identify to peers
    let transport = transport_clone.clone();
    let peer_map = client.peer_map.clone();
    let in_destination = client.in_destination.clone();
    let out_link_loop = async move || {
      let mut out_link_events = transport.lock().await.out_link_events();
      // buffer to contain [destination_hash, nonce] to sign over
      let mut sig_buffer = [0u8; SIG_BUFFER_SIZE];
      // outgoing auth data [auth_byte, destination_hash, signature]
      let mut auth_buffer = [PEER_AUTH_BYTE; 1 + AUTH_SIZE];
      sig_buffer[..ADDRESS_HASH_SIZE].copy_from_slice(in_destination_hash.as_slice());
      auth_buffer[1..1 + ADDRESS_HASH_SIZE].copy_from_slice(in_destination_hash.as_slice());
      loop {
        match out_link_events.recv().await {
          // check if this is one of our links
          // TODO: should we use a constant time lookup for out links?
          Ok(link_event) => if peer_map.lock().await.values()
            .find(|peer| peer.out_link_id == Some(link_event.id))
            .is_some()
          {
            match link_event.event {
              LinkEvent::Data(payload) => {
                let transport_guard = transport.lock().await;
                if let Some(link) = transport_guard
                  .find_out_link(&link_event.address_hash).await.clone()
                {
                  // send peer identification
                  drop(transport_guard);
                  log::debug!("got nonce: sending peer auth on link {} to {}",
                    link_event.id, link_event.address_hash);
                  // copy nonce
                  sig_buffer[ADDRESS_HASH_SIZE..].copy_from_slice(payload.as_slice());
                  // sign in_destination + nonce
                  let signature = in_destination.lock().await.identity.sign(&sig_buffer);
                  auth_buffer[1 + ADDRESS_HASH_SIZE..].copy_from_slice(&signature.to_bytes());
                  let link = link.lock().await;
                  let packet = link.data_packet(auth_buffer.as_slice()).unwrap();
                  drop(link);
                  transport.lock().await.send_packet(packet).await;
                  let mut found_peer = false;
                  for peer in peer_map.lock().await.values_mut() {
                    if peer.out_link_id == Some(link_event.id) {
                      peer.sent_auth = true;
                      found_peer = true;
                    }
                  }
                  if !found_peer {
                    log::warn!("could not find peer for out-link {} to set auth_sent flag",
                      link_event.id);
                  }
                } else {
                  log::warn!("could not find out-link {} in transport", link_event.id);
                }
              }
              LinkEvent::Activated => log::debug!("out-link activated: {}", link_event.id),
              LinkEvent::Closed => {
                log::debug!("out-link closed {}", link_event.id);
                // remove closed link
                for peer in peer_map.lock().await.values_mut() {
                  if peer.out_link_id == Some(link_event.id) {
                    let _ = peer.out_link_id.take();
                    peer.sent_auth = false;
                  }
                }
              }
              LinkEvent::Proof(_) => {}
            }
          }
          Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) =>
            log::debug!("recv out-link event lagged: {n}"),
          Err(err) => {
            log::error!("recv out-link event error: {err:?}");
            break
          }
        }
      }
    };
    // upstream link data: put link data into tun
    let transport = transport_clone.clone();
    let tun = client.tun.clone();
    let peer_map = client.peer_map.clone();
    let in_link_auths = client.in_link_auths.clone();
    let in_destination = client.in_destination.clone();
    let network = client.config.network;
    let allow_all = client.config.allow_all;
    let in_link_loop = async move || {
      let peer_map = peer_map.clone();
      let mut nonce_buffer = [0u8; AUTH_NONCE_BYTES];
      let mut in_link_events = transport.lock().await.in_link_events();
      loop {
        match in_link_events.recv().await {
          // check if this is our in-link
          Ok(link_event) => if link_event.address_hash == in_destination_hash {
            match link_event.event {
              LinkEvent::Data(payload) => {
                log::trace!("in-link {} payload ({})", link_event.id, payload.len());
                let data = payload.as_slice();
                if data[0] == 0x0 {
                  // data packet: only forward if peer is identified
                  if let Some(auth) = in_link_auths.lock().await.get(&link_event.id) {
                    if auth.authorized_peer.is_some() {
                      match tun.send(&data[1..]).await {
                        Ok(n) => log::trace!("tun sent {n} bytes"),
                        Err(err) => {
                          log::error!("tun error sending bytes: {err:?}");
                          break
                        }
                      }
                    } else {
                      log::warn!("dropping data packet for unidentified in-link {}", link_event.id);
                    }
                  } else {
                    log::warn!("in-link peers list missing link id {}", link_event.id);
                  }
                } else {
                  // peer auth notification
                  debug_assert_eq!(data[0], PEER_AUTH_BYTE);
                  let close_link = async || {
                    // close the link
                    let transport = transport.lock().await;
                    if let Some(link) = transport.find_in_link(&link_event.id).await.clone() {
                      drop(transport);
                      log::warn!("closing in-link {}", link_event.id);
                      link.lock().await.close();
                      // LinkEvent::Closed handling will take care of cleaning up
                    } else {
                      log::warn!("could not find in-link {}", link_event.id);
                      debug_assert!(false, "could not find in-link {}", link_event.id);
                    }
                  };
                  let auth_data = &data[1..1 + AUTH_SIZE];
                  let address_bytes = match auth_data[..ADDRESS_HASH_SIZE].try_into() {
                    Ok(array) => array,
                    Err(err) => {
                      log::warn!("error parsing peer identification destination hash for \
                        in-link {}: {err:?}", link_event.id);
                      close_link().await;
                      continue
                    }
                  };
                  let peer_dest = AddressHash::new(address_bytes);
                  let mut peer_found = false;
                  for peer in peer_map.lock().await.values_mut() {
                    if peer.dest == peer_dest {
                      peer_found = true;
                      if let Some(link_id) = peer.in_link_id {
                        log::warn!("overwriting in-link id {link_id} for peer {} with link id {}",
                          peer.dest, link_event.id);
                      }
                      peer.in_link_id = Some(link_event.id);
                      if let Err(err) = peer_auth(
                        in_link_auths.clone(), link_event.id, peer, auth_data
                      ).await {
                        log::error!("peer auth error: {err:?}");
                        close_link().await;
                        break
                      }
                    }
                  }
                  if !peer_found {
                    if !allow_all {
                      log::warn!("could not find peer {peer_dest} to validate in-link {}",
                        link_event.id);
                      close_link().await;
                    } else {
                      // allow all mode: add this peer to peer map
                      log::info!("adding new peer: {peer_dest}");
                      if let Err(err) = add_peer(
                        transport.clone(),
                        peer_map.clone(),
                        network,
                        in_destination.lock().await.desc.address_hash,
                        peer_dest
                      ).await {
                        log::warn!("error adding new peer {peer_dest}: {err:?}");
                        close_link().await;
                      } else {
                        if let Some(peer) = peer_map.lock().await.values_mut()
                          .find(|p| p.dest == peer_dest)
                        {
                          peer.in_link_id = Some(link_event.id);
                          if let Err(err) = peer_auth(
                            in_link_auths.clone(), link_event.id, peer, auth_data
                          ).await {
                            log::error!("peer auth error: {err:?}");
                            close_link().await;
                          }
                        } else {
                          log::warn!("peer was removed, closing link");
                          close_link().await;
                        }
                      }
                    }
                  }
                }
              }
              LinkEvent::Activated => {
                log::debug!("in-link activated {}", link_event.id);
                // send nonce to request auth
                OsRng.fill_bytes(&mut nonce_buffer[..]);
                let transport_guard = transport.lock().await;
                if let Some(link) = transport_guard.find_in_link(&link_event.id).await.clone() {
                  drop(transport_guard);
                  log::debug!("sending nonce for in-link {}", link_event.id);
                  let link = link.lock().await;
                  let packet = link.data_packet(&nonce_buffer).unwrap();
                  drop(link);
                  transport.lock().await.send_packet(packet).await;
                } else {
                  log::error!("error sending nonce: could not find in-link for link id {}", link_event.id);
                  panic!("error sending nonce: could not find in-link for link id {}", link_event.id);
                }
                let _ = in_link_auths.lock().await
                  .insert(link_event.id, InLinkAuth::link_open(nonce_buffer));
              }
              LinkEvent::Closed => {
                log::debug!("in-link closed {}", link_event.id);
                // remove closed link
                if in_link_auths.lock().await.remove(&link_event.id).is_none() {
                  log::debug!("closed in-link {} missing from in-link peers list",
                    link_event.id);
                }
                for peer in peer_map.lock().await.values_mut() {
                  if peer.in_link_id == Some(link_event.id) {
                    let _ = peer.in_link_id.take();
                  }
                }
              }
              LinkEvent::Proof(_) => {}
            }
          }
          Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
            log::debug!("recv in-link event lagged: {n}");
          }
          Err(err) => {
            log::error!("recv in-link event error: {err:?}");
            break
          }
        }
      }
    };
    // tun loop: read data from tun and send on out-links
    let transport = transport_clone.clone();
    let peer_map = client.peer_map.clone();
    let tun = client.tun.clone();
    let tun_loop = async move || {
      let mut buf = vec![0x0];
      while let Ok(bytes) = tun.read().await {
        log::trace!("got tun bytes ({})", bytes.len());
        if let Ok((ip_header, _)) = etherparse::IpHeaders::from_slice(bytes.as_slice())
          .map_err(|err| log::error!("couldn't parse packet from tun: {err:?}"))
        {
          let mut destination_ip = None;
          if let Some((ipv4_header, _)) = ip_header.ipv4() {
            destination_ip = Some(IpAddr::from(ipv4_header.destination));
          } else if let Some((ipv6_header, _)) = ip_header.ipv6() {
            destination_ip = Some(IpAddr::from(ipv6_header.destination));
          } else {
            log::error!("failed to get ipv4 or ipv6 headers from ip header: {ip_header:?}");
          }
          if let Some(destination_ip) = destination_ip {
            let peer_map_guard = peer_map.lock().await;
            if let Some(peer) = peer_map_guard.get(&destination_ip).cloned() {
              if !peer.sent_auth {
                // peer has not sent auth
                continue
              }
              drop(peer_map_guard);
              if let Some(link_id) = peer.out_link_id.as_ref() {
                let transport_guard = transport.lock().await;
                if let Some(link) = transport_guard.find_out_link(&peer.dest).await.clone() {
                  drop(transport_guard);
                  log::trace!("sending to {} on out-link {link_id}", peer.dest);
                  buf.extend_from_slice(&bytes);
                  let link = link.lock().await;
                  let packet = link.data_packet(&buf).unwrap();
                  drop(link);
                  transport.lock().await.send_packet(packet).await;
                  buf.truncate(1);
                } else {
                  log::warn!("could not get out-link {link_id} for peer {}", peer.dest);
                }
              }
            }
          }
        }
      }
    };
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(());
    let run_handle = tokio::spawn(async move {
      tokio::select!{
        _ = announce_send_loop() => log::info!("announce send loop exited: shutting down"),
        _ = announce_recv_loop() => log::info!("announce recv loop exited: shutting down"),
        _ = out_link_loop() => log::info!("out-link loop exited: shutting down"),
        _ = in_link_loop() => log::info!("in-link loop exited: shutting down"),
        _ = tun_loop() => log::info!("tun loop exited: shutting down"),
        _ = shutdown_rx.changed() => log::info!("shutdown requested"),
        _ = tokio::signal::ctrl_c() => log::info!("got ctrl-c: shutting down")
      }
    });
    client.run_handle = Some((run_handle, shutdown_tx));
    Ok(client)
  }

  /// Check if the client task is still running
  pub fn is_running(&self) -> bool {
    self.run_handle.as_ref().map(|(handle, _)| handle.is_finished()).unwrap_or(false)
  }

  /// Blocks until the running task exits. This will run forever unless a task exits
  /// unexpectedly.
  pub async fn await_finished(mut self) {
    if let Some((handle, _)) = self.run_handle.take() {
      match handle.await {
        Ok(()) => log::info!("client finished"),
        Err(err) => log::error!("error joining client task: {err}")
      }
    }
  }

  /// Shutdown client task (if running) and cleanup acquired resources
  pub async fn shutdown(mut self) {
    if let Some((handle, shutdown_tx)) = self.run_handle.take() {
      log::debug!("sending shutdown signal");
      match shutdown_tx.send(()) {
        Ok(()) => match tokio::time::timeout(time::Duration::from_secs(5), handle).await {
          Ok(result) => match result {
            Ok(()) => log::info!("client shutdown"),
            Err(err) => log::error!("error joining client task: {err}")
          }
          Err(elapsed) => log::error!("client timed out waiting for task to end: {elapsed}")
        }
        Err(err) => log::error!("error sending shutdown signal: {err}")
      }
    }
  }

  /// Return the current peer list
  pub async fn peer_list(&self) -> BTreeMap<AddressHash, PeerInfo> {
    self.peer_map.lock().await.iter().map(|(ip_addr, peer)|{
      (peer.dest, PeerInfo {
        dest: peer.dest,
        ip_addr: *ip_addr,
        in_link_id: peer.in_link_id,
        out_link_id: peer.out_link_id,
      })
    }).collect()
  }

  /// Add peer
  pub async fn peer_add(&self, destination: AddressHash) -> Result<(), PeerAddError> {
    add_peer(
      self.transport.clone(),
      self.peer_map.clone(),
      self.config.network,
      self.in_destination.lock().await.desc.address_hash,
      destination
    ).await
  }

  /// Remove peer and close link
  pub async fn peer_remove(&self, destination: AddressHash)
    -> Result<(), PeerRemoveError>
  {
    let mut peer_map = self.peer_map.lock().await;
    let ip = destination_to_ip(destination, self.config.network).addr();
    if let Some(peer) = peer_map.get(&ip) {
      if peer.dest != destination {
        Err(PeerRemoveError::NotFound)
      } else {
        // safe to unwrap: we checked with get(&ip) above
        let peer = peer_map.remove(&ip).unwrap();
        drop(peer_map);
        if let Some(link_id) = peer.out_link_id {
          let transport = self.transport.lock().await;
          if let Some(link) = transport.find_out_link(&peer.dest).await.clone() {
            drop(transport);
            log::debug!("closing out-link {link_id} for peer {}", peer.dest);
            link.lock().await.close();
          }
        }
        if let Some(link_id) = peer.in_link_id {
          let transport = self.transport.lock().await;
          if let Some(link) = transport.find_in_link(&link_id).await.clone() {
            drop(transport);
            log::debug!("closing in-link {link_id} for peer {}", peer.dest);
            link.lock().await.close();
          }
        }
        log::debug!("removed peer {destination}");
        Ok(())
      }
    } else {
      if cfg!(debug_assertions) {
        // sanity check that the destination doesn't exist under any other ips
        for peer in peer_map.values() {
          debug_assert_ne!(peer.dest, destination);
        }
      }
      Err(PeerRemoveError::NotFound)
    }
  }

  /// Remove all peers and close links
  pub async fn clear_peers(&self) {
    let mut peer_map = self.peer_map.lock().await;
    for peer in peer_map.values() {
      if let Some(link_id) = peer.out_link_id {
        let transport = self.transport.lock().await;
        if let Some(link) = transport.find_out_link(&peer.dest).await.clone() {
          drop(transport);
          log::debug!("closing out-link {link_id} for peer {}", peer.dest);
          link.lock().await.close();
        }
      }
      if let Some(link_id) = peer.in_link_id {
        let transport = self.transport.lock().await;
        if let Some(link) = transport.find_in_link(&link_id).await.clone() {
          drop(transport);
          log::debug!("closing in-link {link_id} for peer {}", peer.dest);
          link.lock().await.close();
        }
      }
    }
    peer_map.clear();
    log::debug!("peer map cleared");
  }

  async fn new(
    config: Config, transport: Arc<tokio::sync::Mutex<Transport>>, id: PrivateIdentity
  ) -> Result<Self, ClientError> {
    // create in destination
    let in_destination = transport.lock().await
      .add_destination(id, DestinationName::new("rns_vpn", "client")).await;
    let in_destination_hash = in_destination.lock().await.desc.address_hash;
    log::info!("created destination: {}",
      format!("{}", in_destination_hash).trim_matches('/'));
    let local_ip = destination_to_ip(in_destination_hash, config.network);
    // set up peer map
    if config.peers.is_empty() {
      log::warn!("no peers configured");
    }
    let peer_map = {
      let mut peer_map = BTreeMap::<IpAddr, Peer>::new();
      for dest in config.peers.iter() {
        let dest = match AddressHash::new_from_hex_string(dest.as_str()) {
          Ok(dest) => dest,
          Err(err) => {
            log::error!("error parsing peer destination hash: {err:?}");
            return Err(ClientError::ConfigError(
              format!("error parsing peer destination hash: {err:?}")))
          }
        };
        let peer = Peer::new(dest);
        let ip = destination_to_ip(dest, config.network);
        if ip == local_ip {
          log::error!("the IP for peer {dest} conflicts with the local IP: {local_ip}");
          return Err(ClientError::ConfigError(format!(
            "the IP for peer {dest} conflicts with the local IP: {local_ip}")))
        }
        if let Some(existing_peer) = peer_map.insert(ip.addr(), peer) {
          log::error!(
            "the configured peer destinations ({}, {dest}) map to the same IP: {ip}",
            existing_peer.dest);
          return Err(ClientError::ConfigError(format!(
              "the configured peer destinations ({}, {dest}) map to the same IP: {ip}",
              existing_peer.dest)))
        }
      }
      Arc::new(Mutex::new(peer_map))
    };
    let in_link_peers = Arc::new(Mutex::new(BTreeMap::new()));
    let destination_hash = in_destination.lock().await.desc.address_hash;
    let vpn_ip = destination_to_ip(destination_hash, config.network);
    let tun = Arc::new(Tun::new(vpn_ip)?);
    let run_handle = None;
    let client = Client {
      config, transport, in_destination, tun, peer_map, in_link_auths: in_link_peers,
      run_handle
    };
    Ok(client)
  }
}

impl Drop for Client {
  fn drop(&mut self) {
    if let Some((_handle, shutdown_tx)) = self.run_handle.take() {
      log::debug!("sending shutdown signal");
      match shutdown_tx.send(()) {
        // note we can't await on the task handle here because drop is not async
        // TODO: use nightly AsyncDrop trait?
        Ok(()) => {}
        Err(err) => log::error!("error sending shutdown signal: {err}")
      }
    }
  }
}

impl Tun {
  pub fn new(ip: IpNet) -> Result<Self, ClientError> {
    log::debug!("creating tun device");
    let ip: IpNet = ip.into();
    let tun = TokioTun::new("rip%d", TUN_NQUEUES)
      .map_err(ClientError::RiptunError)?;
    log::debug!("created tun device: {}", tun.name());
    log::debug!("adding broadcast ip addr: {ip}");
    let output = std::process::Command::new("ip")
      .arg("addr")
      .arg("add")
      .arg(ip.to_string())
      .arg("brd")
      .arg(ip.addr().to_string())
      .arg("dev")
      .arg(tun.name())
      .output()
      .map_err(ClientError::IpAddBroadcastError)?;
    if !output.status.success() {
      return Err(ClientError::IpAddBroadcastError(
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
      .map_err(ClientError::IpLinkUpError)?;
    if !output.status.success() {
      return Err(ClientError::IpLinkUpError(
        std::io::Error::other(format!("ip link set command failed ({:?})",
          output.status.code()))))
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

impl Drop for Tun {
  fn drop(&mut self) {
    match self.tun.close() {
      Ok(()) => {}
      Err(err) => {
        log::error!("error closing tun device: {err}");
        // try taking down the interface manually
        log::debug!("{} setting link down", self.tun.name());
        if let Ok(output) = std::process::Command::new("ip")
          .arg("link")
          .arg("set")
          .arg("dev")
          .arg(self.tun.name())
          .arg("down")
          .output()
        {
          if !output.status.success() {
            log::error!("ip link down command failed ({:?})", output.status.code())
          }
        }
      }
    }
  }
}

impl std::fmt::Debug for PeerInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
      f.debug_struct("PeerInfo")
        .field("dest", &self.dest.to_string())
        .field("in_link_id", &self.in_link_id.as_ref().map(ToString::to_string))
        .field("out_link_id", &self.out_link_id.as_ref().map(ToString::to_string))
        .finish()
    }
}

impl Peer {
  pub fn new(dest: AddressHash) -> Self {
    Peer {
      dest, verify_key: None, sent_auth: false, in_link_id: None, out_link_id: None,
      received_auth_payload: None
    }
  }
}

impl std::fmt::Debug for Peer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
      f.debug_struct("Peer")
        .field("dest", &self.dest.to_string())
        .field("verify_key", if self.verify_key.is_some() {
          &Some("<verify-key>")
        } else {
          &Option::<&str>::None
        })
        .field("in_link_id", &self.in_link_id.as_ref().map(ToString::to_string))
        .field("out_link_id", &self.out_link_id.as_ref().map(ToString::to_string))
        .field("sent_auth", &self.sent_auth)
        .field("received_auth_payload", if self.received_auth_payload.is_some() {
          &Some("<auth-payload>")
        } else {
          &Option::<&str>::None
        })
        .finish()
    }
}

impl InLinkAuth {
  pub fn link_open(sent_nonce: [u8; AUTH_NONCE_BYTES]) -> Self {
    InLinkAuth {
      link_open_ts: time::Instant::now(),
      sent_nonce,
      authorized_peer: None
    }
  }
}

impl std::fmt::Debug for InLinkAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
      f.debug_struct("InLinkAuth")
        .field("link_open_ts", &self.link_open_ts)
        .field("sent_nonce", &format!("{:?}", self.sent_nonce))
        .field("authorized_peer", &self.authorized_peer.as_ref().map(ToString::to_string))
        .finish()
    }
}

fn destination_to_ip(destination: AddressHash, prefix: cidr::Ipv4Cidr) -> IpNet {
  let n = u32::from_be_bytes((&destination.as_slice()[12..16]).try_into().unwrap());
  let network_bits = prefix.mask().to_bits();
  let host_bits = (!network_bits) & n;
  let addr = Ipv4Addr::from_bits(prefix.first_address().to_bits() | host_bits);
  IpNet::new(IpAddr::V4(addr), network_bits.count_ones() as u8).unwrap()
}

async fn add_peer(
  transport: Arc<Mutex<Transport>>,
  peer_map: Arc<Mutex<BTreeMap<IpAddr, Peer>>>,
  network: cidr::Ipv4Cidr,
  local_in_destination: AddressHash,
  destination: AddressHash
) -> Result<(), PeerAddError> {
  let ip = destination_to_ip(destination, network).addr();
  let local_ip = destination_to_ip(local_in_destination, network).addr();
  if ip == local_ip {
    log::warn!("the IP for peer {destination} conflicts with the local IP: {local_ip}");
    return Err(PeerAddError::IpConflicts(local_in_destination, ip))
  }
  {
    let peer_map = peer_map.lock().await;
    if let Some(existing_peer) = peer_map.get(&ip) {
      if existing_peer.dest == destination {
        log::warn!("peer add ({destination}): already exists");
        return Err(PeerAddError::AlreadyExists)
      } else {
        log::warn!("peer add ({destination}): ip {ip} conflicts with peer {}",
          existing_peer.dest);
        return Err(PeerAddError::IpConflicts(existing_peer.dest, ip))
      }
    }
    drop(peer_map);
  }
  log::debug!("adding peer {destination}");
  let mut peer = Peer::new(destination);
  let transport = transport.lock().await;
  if let Some(dest) = transport.get_out_destination(&destination).await {
    let link = transport.link(dest.lock().await.desc).await;
    drop(transport);
    peer.out_link_id = Some(link.lock().await.id().clone());
    log::debug!("created out-link {} for peer {}",
      peer.out_link_id.as_ref().unwrap(), peer.dest);
  }
  let res = peer_map.lock().await.insert(ip, peer);
  debug_assert!(res.is_none());
  Ok(())
}

async fn peer_auth(
  in_link_auths: Arc<Mutex<BTreeMap<LinkId, InLinkAuth>>>,
  in_link_id: LinkId,
  peer: &mut Peer,
  auth_data: &[u8]
) -> Result<(), PeerAuthError> {
  let mut sig_buffer = [0u8; SIG_BUFFER_SIZE];
  // validate signature
  if let Some(verify_key) = peer.verify_key.as_ref() {
    match Signature::from_slice(&auth_data[ADDRESS_HASH_SIZE..]) {
      Ok(signature) => {
        sig_buffer[..ADDRESS_HASH_SIZE].copy_from_slice(&auth_data[..ADDRESS_HASH_SIZE]);
        if let Some(auth) = in_link_auths.lock().await.get_mut(&in_link_id) {
          sig_buffer[ADDRESS_HASH_SIZE..].copy_from_slice(&auth.sent_nonce);
        } else {
          log::error!("in-link id {} missing from in-link peers list", in_link_id);
          return Err(PeerAuthError::MissingInLinkAuth(in_link_id))
        }
        if verify_key.verify_strict(&sig_buffer, &signature).is_ok() {
          log::debug!("authorized remote peer {} on in-link {}", peer.dest, in_link_id);
          if let Some(auth) = in_link_auths.lock().await.get_mut(&in_link_id) {
            debug_assert!(auth.authorized_peer.is_none());
            if let Some(dest) = auth.authorized_peer {
              if dest != peer.dest {
                log::warn!("in-link peers list already has peer {dest} for in-link {}",
                  in_link_id);
                return Err(PeerAuthError::InLinkAlreadyAuthorized(in_link_id, dest))
              }
            }
            auth.authorized_peer = Some(peer.dest);
          } else {
            log::error!("in-link id {} missing from in-link peers list", in_link_id);
            return Err(PeerAuthError::MissingInLinkAuth(in_link_id))
          }
        } else {
          log::warn!("auth signature failed for peer {} on in-link {}",
            peer.dest, in_link_id);
          return Err(PeerAuthError::InvalidSignature(in_link_id, peer.dest))
        }
      }
      Err(err) => {
        log::error!("failed to load signature bytes for peer {} auth packet: {err}",
          peer.dest);
        return Err(PeerAuthError::InvalidSignature(in_link_id, peer.dest))
      }
    }
  } else {
    // we don't have the peer's verify key yet: stash the auth data until it can be
    // verified
    log::debug!("could not yet authenticate peer {} on in-link {}: missing verify key",
      peer.dest, in_link_id);
    if let Ok(auth_payload) = auth_data.try_into() {
      peer.received_auth_payload = Some(auth_payload);
    } else {
      log::warn!("invalid auth payload size, closing in-link {}", in_link_id);
      return Err(PeerAuthError::InvalidPayload(in_link_id))
    }
  }
  Ok(())
}

#[cfg(test)]
mod tests {
  use reticulum::hash::AddressHash;
  use super::*;
  #[test]
  fn dest_to_ip() {
    use std::str::FromStr;
    let destination =
      AddressHash::new_from_hex_string("fb08aff16ec6f5ccf0d3eb179028e9c3").unwrap();
    // 0xe9 = 233, 0xc3 = 195
    let prefix = cidr::Ipv4Cidr::from_str("10.1.0.0/16").unwrap();
    let ip = destination_to_ip(destination, prefix);
    assert_eq!(ip.addr(), std::net::IpAddr::from_str("10.1.233.195").unwrap());
  }
}
