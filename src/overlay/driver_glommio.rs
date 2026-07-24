use std::{
    cell::RefCell,
    collections::{BTreeMap, HashMap, VecDeque},
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    rc::Rc,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Result, anyhow};
use futures::{AsyncReadExt, AsyncWriteExt};
use glommio::{
    Task,
    net::{TcpStream, UdpSocket},
    spawn_local,
    timer::timeout,
};
use rand::{RngCore, SeedableRng, rngs::StdRng};
use solana_sdk::signature::Keypair;

use crate::{
    thread_manager::CancelRx,
    types::{PacketInfo, PacketView},
};

use super::{
    OverlayConfig, OverlayIdentity, OverlayMode,
    env::{IpFamily, OverlayEnv, SocketId, TcpEvent, TcpId},
    repair::{OverlayRepairCommand, RepairRoute, RepairStore, SharedRepairView},
    service::{CoreEvent, OverlayCore},
    transport::{OverlayQuicTransport, OverlayStreamId, TransportOptions},
};

const RECEIVE_POLL_INTERVAL: Duration = Duration::from_millis(10);
const SOURCE_POLL_INTERVAL: Duration = Duration::from_millis(1);
const MIN_RECEIVE_WAIT: Duration = Duration::from_micros(100);
const UDP_BUFFER_SIZE: usize = 65_535;
/// Cadence for republishing the repair peer view to the repair manager.
const REPAIR_VIEW_INTERVAL: Duration = Duration::from_secs(1);

/// Sink-mode requester wiring (nat-traversal.md §6.4): repair commands in
/// from the sink demux, nonce-tagged responses back to the repair manager,
/// and the sampled peer view published for `OverlayRepairPeerSource`.
pub struct OverlayRepairRequester {
    pub cmd_rx: kanal::AsyncReceiver<OverlayRepairCommand>,
    pub resp_tx: kanal::AsyncSender<(RepairRoute, PacketInfo)>,
    pub view: SharedRepairView,
}

/// Live TCP conns the env may hold (§6.3 UPnP: the port-map client opens at
/// most one or two at a time).
const MAX_TCP_CONNS: usize = 8;

/// Env-side state of one production TCP stream (§6.3 UPnP). The driver
/// spawns a task owning the `glommio::net::TcpStream`; this shared cell
/// carries the core's queued writes and close request to it.
struct TcpConnState {
    to: SocketAddr,
    out: VecDeque<Vec<u8>>,
    closed: bool,
    /// A driver task has been spawned for this conn.
    spawned: bool,
}

/// Production side of the `OverlayEnv` seam: real sockets, the OS clock, and
/// OS-seeded randomness. `send` only queues; the driver loop flushes between
/// core events so the core itself never blocks.
struct GlommioEnv {
    /// Indexed by `SocketId`; slots are tombstoned (never shifted) on
    /// `close` so ids stay stable. Slot 0 is always the primary socket.
    /// `Rc` so per-helper-socket forwarder tasks can share the socket with
    /// the driver's send path (§6.2.3 fresh-source dial-back binds).
    sockets: Vec<Option<Rc<UdpSocket>>>,
    out: VecDeque<(SocketId, SocketAddr, Vec<u8>)>,
    /// TCP streams keyed by id; tasks are reconciled by the driver loop.
    tcp: BTreeMap<TcpId, Rc<RefCell<TcpConnState>>>,
    next_tcp: u64,
    rng: StdRng,
}

impl GlommioEnv {
    /// Bind the primary v4 socket and, when configured, the secondary v6
    /// socket (§6.3 dual-stack). Returns the v6 socket's id for the
    /// transport's egress selection.
    fn bind_primary(addr: SocketAddr, addr_v6: Option<SocketAddr>) -> Result<(Self, Option<SocketId>)> {
        let socket = UdpSocket::bind(addr)
            .map_err(|e| anyhow!("failed to bind overlay QUIC socket {addr}: {e}"))?;
        let mut sockets = vec![Some(Rc::new(socket))];
        let mut socket_v6 = None;
        if let Some(addr_v6) = addr_v6 {
            let socket = UdpSocket::bind(addr_v6)
                .map_err(|e| anyhow!("failed to bind overlay IPv6 socket {addr_v6}: {e}"))?;
            socket_v6 = Some(SocketId(sockets.len() as u32));
            sockets.push(Some(Rc::new(socket)));
        }
        Ok((
            Self {
                sockets,
                out: VecDeque::new(),
                tcp: BTreeMap::new(),
                next_tcp: 0,
                rng: StdRng::from_os_rng(),
            },
            socket_v6,
        ))
    }

    fn primary(&self) -> Rc<UdpSocket> {
        self.sockets[0]
            .clone()
            .expect("primary overlay socket is never closed")
    }

    async fn flush(&mut self) {
        while let Some((from, to, bytes)) = self.out.pop_front() {
            let Some(Some(socket)) = self.sockets.get(from.0 as usize) else {
                log::warn!("overlay: dropping datagram to {to} from closed/unknown {from}");
                continue;
            };
            if let Err(e) = socket.send_to(&bytes, to).await {
                log::warn!("overlay: failed to send datagram to {to}: {e}");
            }
        }
    }
}

impl OverlayEnv for GlommioEnv {
    fn now(&self) -> Instant {
        Instant::now()
    }

    fn rng(&mut self) -> &mut dyn RngCore {
        &mut self.rng
    }

    fn send(&mut self, from: SocketId, to: SocketAddr, datagram: &[u8]) {
        self.out.push_back((from, to, datagram.to_vec()));
    }

    fn bind(&mut self, port: Option<u16>, family: IpFamily) -> Result<SocketId> {
        let addr = match family {
            IpFamily::V4 => SocketAddr::from((Ipv4Addr::UNSPECIFIED, port.unwrap_or(0))),
            IpFamily::V6 => SocketAddr::from((Ipv6Addr::UNSPECIFIED, port.unwrap_or(0))),
        };
        let socket = UdpSocket::bind(addr)
            .map_err(|e| anyhow!("failed to bind overlay helper socket {addr}: {e}"))?;
        let id = SocketId(u32::try_from(self.sockets.len())?);
        self.sockets.push(Some(Rc::new(socket)));
        Ok(id)
    }

    fn close(&mut self, socket: SocketId) {
        // Slot 0 is the primary socket and outlives the process.
        if socket != SocketId::PRIMARY
            && let Some(slot) = self.sockets.get_mut(socket.0 as usize)
        {
            *slot = None;
        }
    }

    fn tcp_connect(&mut self, to: SocketAddr) -> Result<TcpId> {
        // Reap conns the core closed whose tasks have finished with them.
        self.tcp
            .retain(|_, state| !(state.borrow().closed && Rc::strong_count(state) == 1));
        if self.tcp.len() >= MAX_TCP_CONNS {
            return Err(anyhow!("overlay TCP conn limit reached ({MAX_TCP_CONNS})"));
        }
        let id = TcpId(self.next_tcp);
        self.next_tcp += 1;
        self.tcp.insert(
            id,
            Rc::new(RefCell::new(TcpConnState {
                to,
                out: VecDeque::new(),
                closed: false,
                spawned: false,
            })),
        );
        Ok(id)
    }

    fn tcp_send(&mut self, conn: TcpId, bytes: &[u8]) {
        if let Some(state) = self.tcp.get(&conn) {
            let mut state = state.borrow_mut();
            if !state.closed {
                state.out.push_back(bytes.to_vec());
            }
        }
    }

    fn tcp_close(&mut self, conn: TcpId) {
        if let Some(state) = self.tcp.get(&conn) {
            state.borrow_mut().closed = true;
        }
    }
}

/// Datagrams read off helper sockets by their forwarder tasks, drained by the
/// driver loop into the core.
type HelperInbound = Rc<RefCell<VecDeque<(SocketId, SocketAddr, Vec<u8>)>>>;

/// TCP events produced by per-conn tasks (§6.3 UPnP), drained into the core.
type TcpInbound = Rc<RefCell<VecDeque<TcpEvent>>>;

/// Default gateway of the host, from the kernel routing table (Linux).
/// Best-effort: `None` simply leaves the §6.3 port-map ladder disabled.
fn discover_default_gateway() -> Option<Ipv4Addr> {
    let routes = std::fs::read_to_string("/proc/net/route").ok()?;
    for line in routes.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        // Destination 00000000 = the default route; gateway is
        // little-endian hex.
        if fields.len() >= 3 && fields[1] == "00000000" {
            let gateway = u32::from_str_radix(fields[2], 16).ok()?;
            let ip = Ipv4Addr::from(gateway.to_le_bytes());
            if !ip.is_unspecified() {
                return Some(ip);
            }
        }
    }
    None
}

/// The local IP the OS would source traffic toward `gateway` from — what
/// PCP/UPnP must present when `bind_addr` is unspecified. A connected UDP
/// socket never touches the network.
fn local_ip_toward(gateway: SocketAddr) -> Option<std::net::IpAddr> {
    let socket = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
    socket.connect(gateway).ok()?;
    Some(socket.local_addr().ok()?.ip())
}

/// Resolve the §6.3 gateway knobs before core construction: explicit config
/// wins, else the default route; the LAN IP presented to the gateway falls
/// back from `bind_addr` to a route lookup.
fn resolve_portmap_config(config: &mut OverlayConfig) {
    if config.gateway_addr.is_none() {
        config.gateway_addr = discover_default_gateway()
            .map(|ip| SocketAddr::new(std::net::IpAddr::V4(ip), 5351));
        if let Some(gateway) = config.gateway_addr {
            log::info!("overlay: discovered default gateway {gateway} for port mapping");
        }
    }
    if let Some(gateway) = config.gateway_addr
        && config.portmap_local_ip.is_none()
        && config.bind_addr.ip().is_unspecified()
    {
        config.portmap_local_ip = local_ip_toward(gateway);
    }
}

/// Spawn a task per TCP conn the core opened (§6.3 UPnP): connect, flush the
/// core's queued writes, and feed reads back as events. Tasks self-terminate
/// on close/EOF; finished conns are reaped by the env on the next connect.
fn reconcile_tcp_tasks(
    env: &GlommioEnv,
    tasks: &mut HashMap<u64, Task<()>>,
    inbound: &TcpInbound,
) {
    tasks.retain(|id, _| env.tcp.contains_key(&TcpId(*id)));
    for (&id, state) in env.tcp.iter() {
        if state.borrow().spawned {
            continue;
        }
        state.borrow_mut().spawned = true;
        let state = state.clone();
        let inbound = inbound.clone();
        let task = spawn_local(async move {
            let to = state.borrow().to;
            let connect = timeout(Duration::from_secs(5), TcpStream::connect(to)).await;
            let mut stream = match connect {
                Ok(stream) => stream,
                Err(e) => {
                    log::debug!("overlay: tcp connect to {to} failed: {e}");
                    state.borrow_mut().closed = true;
                    inbound.borrow_mut().push_back(TcpEvent::Closed(id));
                    return;
                }
            };
            inbound.borrow_mut().push_back(TcpEvent::Connected(id));
            let mut buf = vec![0u8; 16_384];
            loop {
                let pending: Vec<Vec<u8>> = state.borrow_mut().out.drain(..).collect();
                for chunk in pending {
                    if stream.write_all(&chunk).await.is_err() {
                        state.borrow_mut().closed = true;
                        inbound.borrow_mut().push_back(TcpEvent::Closed(id));
                        return;
                    }
                }
                if state.borrow().closed {
                    return;
                }
                match timeout(Duration::from_millis(20), async {
                    stream
                        .read(&mut buf)
                        .await
                        .map_err(glommio::GlommioError::from)
                })
                .await
                {
                    Ok(0) => {
                        state.borrow_mut().closed = true;
                        inbound.borrow_mut().push_back(TcpEvent::Closed(id));
                        return;
                    }
                    Ok(read) => {
                        inbound
                            .borrow_mut()
                            .push_back(TcpEvent::Data(id, buf[..read].to_vec()));
                    }
                    // Receive window elapsed; flush writes and poll again.
                    Err(_) => {}
                }
            }
        });
        tasks.insert(id.0, task);
    }
}

/// Spawn a forwarder task for every open helper socket (index ≥ 1) that lacks
/// one, and cancel forwarders whose socket the core has closed. Helper sockets
/// are short-lived (a dial-back probe), so this set is normally empty.
async fn reconcile_helper_readers(
    env: &GlommioEnv,
    readers: &mut HashMap<u32, Task<()>>,
    inbound: &HelperInbound,
) {
    let closed: Vec<u32> = readers
        .keys()
        .copied()
        .filter(|&idx| !matches!(env.sockets.get(idx as usize), Some(Some(_))))
        .collect();
    for idx in closed {
        if let Some(task) = readers.remove(&idx) {
            task.cancel().await;
        }
    }
    for idx in 1..env.sockets.len() {
        if readers.contains_key(&(idx as u32)) {
            continue;
        }
        let Some(Some(socket)) = env.sockets.get(idx) else {
            continue;
        };
        let socket = socket.clone();
        let inbound = inbound.clone();
        let socket_id = SocketId(idx as u32);
        let task = spawn_local(async move {
            let mut buf = vec![0u8; UDP_BUFFER_SIZE];
            loop {
                match socket.recv_from(&mut buf).await {
                    Ok((len, from)) => {
                        inbound
                            .borrow_mut()
                            .push_back((socket_id, from, buf[..len].to_vec()));
                    }
                    Err(e) => {
                        log::debug!("overlay: helper {socket_id} recv ended: {e}");
                        break;
                    }
                }
            }
        });
        readers.insert(idx as u32, task);
    }
}

async fn run_driver(
    identity: &OverlayIdentity,
    keypair: Arc<Keypair>,
    config: OverlayConfig,
    source_rx: Option<kanal::AsyncReceiver<PacketInfo>>,
    filter_tx: kanal::AsyncSender<PacketInfo>,
    repair_store: impl RepairStore,
    repair_requester: Option<OverlayRepairRequester>,
) -> Result<()> {
    let mut config = config;
    resolve_portmap_config(&mut config);
    let (mut env, socket_v6) = GlommioEnv::bind_primary(config.bind_addr, config.bind_addr_v6)?;
    let transport = OverlayQuicTransport::new(
        SocketId::PRIMARY,
        socket_v6,
        identity,
        &TransportOptions::default(),
    )?;
    let source_mode = config.mode == OverlayMode::Source && source_rx.is_some();
    let mut core = OverlayCore::new(transport, &config, keypair, Instant::now());
    let mut buffer = vec![0u8; UDP_BUFFER_SIZE];
    // Stream handle → the local nonce the repair manager matches on.
    let mut outstanding_nonces: BTreeMap<OverlayStreamId, u32> = BTreeMap::new();
    let mut next_view_publish = Instant::now();
    // §6.2.3 fresh-source dial-back binds a helper socket; a per-socket
    // forwarder task reads it into this shared queue, drained each loop.
    let helper_inbound: HelperInbound = Rc::new(RefCell::new(VecDeque::new()));
    let mut helper_readers: HashMap<u32, Task<()>> = HashMap::new();
    // §6.3 UPnP TCP conns: per-conn tasks feed events into this queue.
    let tcp_inbound: TcpInbound = Rc::new(RefCell::new(VecDeque::new()));
    let mut tcp_tasks: HashMap<u64, Task<()>> = HashMap::new();

    loop {
        for (socket, from, bytes) in helper_inbound.borrow_mut().drain(..).collect::<Vec<_>>() {
            core.on_datagram(&mut env, socket, from, &bytes);
        }
        for event in tcp_inbound.borrow_mut().drain(..).collect::<Vec<_>>() {
            core.on_tcp_event(&mut env, event);
        }
        env.flush().await;

        core.on_timer(&mut env);

        if let Some(source_rx) = &source_rx {
            loop {
                match source_rx.try_recv() {
                    Ok(Some(packet)) => core.on_source_packet(&mut env, packet),
                    Ok(None) => break,
                    Err(e) => {
                        log::warn!("overlay: source shred channel closed: {e}");
                        break;
                    }
                }
            }
        }

        if let Some(requester) = &repair_requester {
            while let Ok(Some(command)) = requester.cmd_rx.try_recv() {
                match core.request_repair(&mut env, command.peer, &command.request) {
                    Some(stream) => {
                        outstanding_nonces.insert(stream, command.nonce);
                    }
                    // No connection (or caps): silence is fine — the repair
                    // manager's 200ms timeout re-samples another peer.
                    None => {}
                }
            }
            let now = Instant::now();
            if now >= next_view_publish {
                next_view_publish = now + REPAIR_VIEW_INTERVAL;
                let view = core.repair_peer_view(now);
                if let Ok(mut shared) = requester.view.write() {
                    *shared = view;
                }
            }
        }

        env.flush().await;
        while let Some(event) = core.poll_event() {
            match event {
                CoreEvent::ShredForFilter(packet) => {
                    if let Err(e) = filter_tx.send(packet).await {
                        log::warn!("overlay: failed to forward shred to filter: {e}");
                    }
                }
                CoreEvent::PeerConnected { peer, pubkey } => {
                    log::debug!("overlay: peer {peer} connected, identity {pubkey:?}");
                }
                CoreEvent::PeerDisconnected { peer, reason } => {
                    log::debug!("overlay: peer {peer} disconnected: {reason}");
                }
                // Serving side of §6.4: the store lookup lives here in the
                // driver (fjall blocks); the sans-IO core only frames the
                // exchange. Same lookups as repair_delivery's UDP server.
                CoreEvent::RepairRequest { stream, request, .. } => {
                    core.on_repair_response(&mut env, stream, repair_store.lookup(&request));
                }
                // Requester side: a concluded stream becomes a UDP-shaped
                // response (shred ‖ nonce LE) so the repair manager's
                // outstanding store and packet-filter path treat both
                // worlds identically. NotFound and failures stay silent —
                // the manager's 200ms timeout re-samples another peer.
                CoreEvent::RepairResponse { stream, peer, shred } => {
                    let nonce = outstanding_nonces.remove(&stream);
                    let (Some(nonce), Some(bytes), Some(requester)) =
                        (nonce, shred, repair_requester.as_ref())
                    else {
                        continue;
                    };
                    let mut tagged = bytes;
                    tagged.extend_from_slice(&nonce.to_le_bytes());
                    let Ok(view) = PacketView::try_from(tagged.as_slice()) else {
                        log::debug!("overlay: oversized repair response from {peer}; dropped");
                        continue;
                    };
                    let packet = PacketInfo::new(view);
                    if let Err(e) = requester
                        .resp_tx
                        .send((RepairRoute::Peer(peer), packet))
                        .await
                    {
                        log::warn!("overlay: failed to forward repair response: {e}");
                    }
                }
                CoreEvent::RepairFailed { stream, peer } => {
                    outstanding_nonces.remove(&stream);
                    log::debug!("overlay: repair stream to {peer} failed");
                }
            }
        }
        env.flush().await;
        // Spawn/cancel forwarder tasks for helper sockets the core bound or
        // closed this iteration (§6.2.3 dial-back), and per-conn TCP tasks
        // for the §6.3 UPnP conversation.
        reconcile_helper_readers(&env, &mut helper_readers, &helper_inbound).await;
        reconcile_tcp_tasks(&env, &mut tcp_tasks, &tcp_inbound);

        let now = Instant::now();
        let mut wait = core
            .poll_timeout()
            .map(|due| due.saturating_duration_since(now))
            .unwrap_or(RECEIVE_POLL_INTERVAL)
            .min(RECEIVE_POLL_INTERVAL);
        if source_mode {
            wait = wait.min(SOURCE_POLL_INTERVAL);
        }
        let primary = env.primary();
        let received = timeout(wait.max(MIN_RECEIVE_WAIT), primary.recv_from(&mut buffer)).await;
        match received {
            Ok((len, from)) => {
                core.on_datagram(&mut env, SocketId::PRIMARY, from, &buffer[..len]);
                env.flush().await;
            }
            Err(_) => {
                // Receive window elapsed; due deadlines fire at the top of
                // the next iteration.
            }
        }
    }
}

pub async fn start_overlay_runner(
    exit: CancelRx,
    keypair: Arc<Keypair>,
    config: OverlayConfig,
    source_rx: Option<kanal::AsyncReceiver<PacketInfo>>,
    filter_tx: kanal::AsyncSender<PacketInfo>,
    repair_store: impl RepairStore + 'static,
    repair_requester: Option<OverlayRepairRequester>,
) -> Result<()> {
    let identity = OverlayIdentity::from_keypair(&keypair)?;
    log::info!("overlay identity: {}", identity.pubkey);

    let runner_task = spawn_local(async move {
        if let Err(e) = run_driver(
            &identity,
            keypair,
            config,
            source_rx,
            filter_tx,
            repair_store,
            repair_requester,
        )
        .await
        {
            log::error!("overlay: driver stopped: {e}");
        }
    });

    exit.await;
    runner_task.cancel().await;
    Ok(())
}
