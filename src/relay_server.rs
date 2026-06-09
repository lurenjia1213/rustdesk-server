use async_speed_limit::Limiter;
use async_trait::async_trait;
use dashmap::{DashMap, DashSet};
use hbb_common::{
    bail,
    bytes::Bytes,
    futures_util::{sink::SinkExt, stream::StreamExt},
    log,
    protobuf::Message as _,
    rendezvous_proto::*,
    sleep,
    tcp::{listen_any, FramedStream},
    timeout,
    tokio::{
        self,
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
        time::{interval, Duration},
    },
    ResultType,
};
use sodiumoxide::crypto::sign;
use std::{
    io::prelude::*,
    io::Error,
    net::SocketAddr,
    sync::atomic::{AtomicUsize, Ordering},
};

type Usage = (usize, usize, usize, usize);

type PeerEntry = (usize, Box<dyn StreamTrait>); // (insert_id, stream)

lazy_static::lazy_static! {
    // DashMap/DashSet: shard-level locking for low contention under high concurrency
    static ref PEERS: DashMap<String, PeerEntry> = Default::default();
    static ref USAGE: DashMap<String, Usage> = Default::default();
    static ref BLACKLIST: DashSet<String> = Default::default();
    static ref BLOCKLIST: DashSet<String> = Default::default();
}

static PEER_INSERT_COUNTER: AtomicUsize = AtomicUsize::new(0);
static DOWNGRADE_THRESHOLD_100: AtomicUsize = AtomicUsize::new(66); // 0.66
static DOWNGRADE_START_CHECK: AtomicUsize = AtomicUsize::new(1_800_000); // in ms
static LIMIT_SPEED: AtomicUsize = AtomicUsize::new(4 * 1024 * 1024); // in bit/s
static TOTAL_BANDWIDTH: AtomicUsize = AtomicUsize::new(1024 * 1024 * 1024); // in bit/s
static SINGLE_BANDWIDTH: AtomicUsize = AtomicUsize::new(16 * 1024 * 1024); // in bit/s
const BLACKLIST_FILE: &str = "blacklist.txt";
const BLOCKLIST_FILE: &str = "blocklist.txt";

#[tokio::main(flavor = "multi_thread")]
pub async fn start(port: &str, key: &str) -> ResultType<()> {
    let key = get_server_sk(key);
    if let Ok(mut file) = std::fs::File::open(BLACKLIST_FILE) {
        let mut contents = String::new();
        if file.read_to_string(&mut contents).is_ok() {
            for x in contents.lines() {
                if let Some(ip) = x.split_whitespace().next() {
                    BLACKLIST.insert(ip.to_owned());
                }
            }
        }
    }
    log::info!("#blacklist({}): {}", BLACKLIST_FILE, BLACKLIST.len());
    if let Ok(mut file) = std::fs::File::open(BLOCKLIST_FILE) {
        let mut contents = String::new();
        if file.read_to_string(&mut contents).is_ok() {
            for x in contents.lines() {
                if let Some(ip) = x.split_whitespace().next() {
                    BLOCKLIST.insert(ip.to_owned());
                }
            }
        }
    }
    log::info!("#blocklist({}): {}", BLOCKLIST_FILE, BLOCKLIST.len());
    let port: u16 = port.parse()?;
    log::info!("Listening on tcp :{}", port);
    let port2 = port + 2;
    log::info!("Listening on websocket :{}", port2);
    let main_task = async move {
        loop {
            log::info!("Start");
            io_loop(listen_any(port).await?, listen_any(port2).await?, &key).await;
        }
    };
    let listen_signal = crate::common::listen_signal();
    tokio::select!(
        res = main_task => res,
        res = listen_signal => res,
    )
}

fn check_params() {
    let tmp = std::env::var("DOWNGRADE_THRESHOLD")
        .map(|x| x.parse::<f64>().unwrap_or(0.))
        .unwrap_or(0.);
    if tmp > 0. {
        DOWNGRADE_THRESHOLD_100.store((tmp * 100.) as _, Ordering::Relaxed);
    }
    log::info!(
        "DOWNGRADE_THRESHOLD: {}",
        DOWNGRADE_THRESHOLD_100.load(Ordering::Relaxed) as f64 / 100.
    );
    let tmp = std::env::var("DOWNGRADE_START_CHECK")
        .map(|x| x.parse::<usize>().unwrap_or(0))
        .unwrap_or(0);
    if tmp > 0 {
        DOWNGRADE_START_CHECK.store(tmp * 1000, Ordering::Relaxed);
    }
    log::info!(
        "DOWNGRADE_START_CHECK: {}s",
        DOWNGRADE_START_CHECK.load(Ordering::Relaxed) / 1000
    );
    let tmp = std::env::var("LIMIT_SPEED")
        .map(|x| x.parse::<f64>().unwrap_or(0.))
        .unwrap_or(0.);
    if tmp > 0. {
        LIMIT_SPEED.store((tmp * 1024. * 1024.) as usize, Ordering::Relaxed);
    }
    log::info!(
        "LIMIT_SPEED: {}Mb/s",
        LIMIT_SPEED.load(Ordering::Relaxed) as f64 / 1024. / 1024.
    );
    let tmp = std::env::var("TOTAL_BANDWIDTH")
        .map(|x| x.parse::<f64>().unwrap_or(0.))
        .unwrap_or(0.);
    if tmp > 0. {
        TOTAL_BANDWIDTH.store((tmp * 1024. * 1024.) as usize, Ordering::Relaxed);
    }

    log::info!(
        "TOTAL_BANDWIDTH: {}Mb/s",
        TOTAL_BANDWIDTH.load(Ordering::Relaxed) as f64 / 1024. / 1024.
    );
    let tmp = std::env::var("SINGLE_BANDWIDTH")
        .map(|x| x.parse::<f64>().unwrap_or(0.))
        .unwrap_or(0.);
    if tmp > 0. {
        SINGLE_BANDWIDTH.store((tmp * 1024. * 1024.) as usize, Ordering::Relaxed);
    }
    log::info!(
        "SINGLE_BANDWIDTH: {}Mb/s",
        SINGLE_BANDWIDTH.load(Ordering::Relaxed) as f64 / 1024. / 1024.
    )
}

async fn check_cmd(cmd: &str, limiter: Limiter) -> String {
    use std::fmt::Write;

    let mut res = String::new();
    let mut fds = cmd.split_whitespace();
    match fds.next() {
        Some("h") => {
            res = format!(
                "{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n",
                "blacklist-add(ba) <ip>",
                "blacklist-remove(br) <ip>",
                "blacklist(b) <ip>",
                "blocklist-add(Ba) <ip>",
                "blocklist-remove(Br) <ip>",
                "blocklist(B) <ip>",
                "downgrade-threshold(dt) [value]",
                "downgrade-start-check(t) [value(second)]",
                "limit-speed(ls) [value(Mb/s)]",
                "total-bandwidth(tb) [value(Mb/s)]",
                "single-bandwidth(sb) [value(Mb/s)]",
                "usage(u)"
            )
        }
        Some("blacklist-add" | "ba") => {
            if let Some(ip) = fds.next() {
                for ip in ip.split('|') {
                    BLACKLIST.insert(ip.to_owned());
                }
            }
        }
        Some("blacklist-remove" | "br") => {
            if let Some(ip) = fds.next() {
                if ip == "all" {
                    BLACKLIST.clear();
                } else {
                    for ip in ip.split('|') {
                        BLACKLIST.remove(ip);
                    }
                }
            }
        }
        Some("blacklist" | "b") => {
            if let Some(ip) = fds.next() {
                res = format!(
                    "{}
",
                    BLACKLIST.contains(ip)
                );
            } else {
                for r in BLACKLIST.iter() {
                    let _ = writeln!(res, "{}", r.key());
                }
            }
        }
        Some("blocklist-add" | "Ba") => {
            if let Some(ip) = fds.next() {
                for ip in ip.split('|') {
                    BLOCKLIST.insert(ip.to_owned());
                }
            }
        }
        Some("blocklist-remove" | "Br") => {
            if let Some(ip) = fds.next() {
                if ip == "all" {
                    BLOCKLIST.clear();
                } else {
                    for ip in ip.split('|') {
                        BLOCKLIST.remove(ip);
                    }
                }
            }
        }
        Some("blocklist" | "B") => {
            if let Some(ip) = fds.next() {
                res = format!(
                    "{}
",
                    BLOCKLIST.contains(ip)
                );
            } else {
                for r in BLOCKLIST.iter() {
                    let _ = writeln!(res, "{}", r.key());
                }
            }
        }
        Some("downgrade-threshold" | "dt") => {
            if let Some(v) = fds.next() {
                if let Ok(v) = v.parse::<f64>() {
                    if v > 0. {
                        DOWNGRADE_THRESHOLD_100.store((v * 100.) as _, Ordering::Relaxed);
                    }
                }
            } else {
                res = format!(
                    "{}\n",
                    DOWNGRADE_THRESHOLD_100.load(Ordering::Relaxed) as f64 / 100.
                );
            }
        }
        Some("downgrade-start-check" | "t") => {
            if let Some(v) = fds.next() {
                if let Ok(v) = v.parse::<usize>() {
                    if v > 0 {
                        DOWNGRADE_START_CHECK.store(v * 1000, Ordering::Relaxed);
                    }
                }
            } else {
                res = format!(
                    "{}s\n",
                    DOWNGRADE_START_CHECK.load(Ordering::Relaxed) / 1000
                );
            }
        }
        Some("limit-speed" | "ls") => {
            if let Some(v) = fds.next() {
                if let Ok(v) = v.parse::<f64>() {
                    if v > 0. {
                        LIMIT_SPEED.store((v * 1024. * 1024.) as _, Ordering::Relaxed);
                    }
                }
            } else {
                res = format!(
                    "{}Mb/s\n",
                    LIMIT_SPEED.load(Ordering::Relaxed) as f64 / 1024. / 1024.
                );
            }
        }
        Some("total-bandwidth" | "tb") => {
            if let Some(v) = fds.next() {
                if let Ok(v) = v.parse::<f64>() {
                    if v > 0. {
                        TOTAL_BANDWIDTH.store((v * 1024. * 1024.) as _, Ordering::Relaxed);
                        limiter.set_speed_limit(TOTAL_BANDWIDTH.load(Ordering::Relaxed) as _);
                    }
                }
            } else {
                res = format!(
                    "{}Mb/s\n",
                    TOTAL_BANDWIDTH.load(Ordering::Relaxed) as f64 / 1024. / 1024.
                );
            }
        }
        Some("single-bandwidth" | "sb") => {
            if let Some(v) = fds.next() {
                if let Ok(v) = v.parse::<f64>() {
                    if v > 0. {
                        SINGLE_BANDWIDTH.store((v * 1024. * 1024.) as _, Ordering::Relaxed);
                    }
                }
            } else {
                res = format!(
                    "{}Mb/s\n",
                    SINGLE_BANDWIDTH.load(Ordering::Relaxed) as f64 / 1024. / 1024.
                );
            }
        }
        Some("usage" | "u") => {
            let mut tmp: Vec<(String, Usage)> = USAGE
                .iter()
                .map(|e| (e.key().clone(), *e.value()))
                .collect();
            tmp.sort_by(|a, b| ((b.1).1).partial_cmp(&(a.1).1).unwrap());
            for (ip, (elapsed, total, highest, speed)) in tmp {
                if elapsed == 0 {
                    continue;
                }
                let _ = writeln!(
                    res,
                    "{}: {}s {:.2}MB {}bit/ms {}bit/ms {}bit/ms",
                    ip,
                    elapsed / 1000,
                    total as f64 / 1024. / 1024. / 8.,
                    highest,
                    total / elapsed,
                    speed
                );
            }
        }
        _ => {}
    }
    res
}

async fn io_loop(listener: TcpListener, listener2: TcpListener, key: &str) {
    check_params();
    let limiter = <Limiter>::new(TOTAL_BANDWIDTH.load(Ordering::Relaxed) as _);

    // Each listener gets its own independent task:
    //   1. No select! overhead — no polling futures that aren't ready.
    //   2. The two listeners accept in true parallel on different executor threads,
    //      so a burst on one port cannot delay accepts on the other.

    let key1 = key.to_owned();
    let limiter1 = limiter.clone();
    let t1 = tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    stream.set_nodelay(true).ok();
                    handle_connection(stream, addr, &limiter1, &key1, false);
                }
                Err(err) => {
                    log::error!("listener.accept failed: {}", err);
                    break;
                }
            }
        }
    });

    let key2 = key.to_owned();
    let limiter2 = limiter.clone();
    let t2 = tokio::spawn(async move {
        loop {
            match listener2.accept().await {
                Ok((stream, addr)) => {
                    stream.set_nodelay(true).ok();
                    handle_connection(stream, addr, &limiter2, &key2, true);
                }
                Err(err) => {
                    log::error!("listener2.accept failed: {}", err);
                    break;
                }
            }
        }
    });

    // If either listener task ends (e.g. OS error), return to let the caller
    // recreate both listeners from scratch.
    tokio::select! {
        _ = t1 => {}
        _ = t2 => {}
    }
}

fn handle_connection(stream: TcpStream, addr: SocketAddr, limiter: &Limiter, key: &str, ws: bool) {
    let ip = hbb_common::try_into_v4(addr).ip();
    if !ws && ip.is_loopback() {
        let limiter = limiter.clone();
        tokio::spawn(async move {
            let mut stream = stream;
            let mut buffer = [0; 1024];
            if let Ok(Ok(n)) = timeout(1000, stream.read(&mut buffer[..])).await {
                if let Ok(data) = std::str::from_utf8(&buffer[..n]) {
                    let res = check_cmd(data, limiter).await;
                    stream.write(res.as_bytes()).await.ok();
                }
            }
        });
        return;
    }
    let ip = ip.to_string();
    if BLOCKLIST.contains(&ip) {
        log::info!("{} blocked", ip);
        return;
    }
    let key = key.to_owned();
    let limiter = limiter.clone();
    tokio::spawn(async move {
        if let Err(err) = make_pair(stream, addr, &key, limiter, ws).await {
            log::error!("Relay session for {} failed: {}", addr, err);
        }
    });
}

async fn make_pair(
    stream: TcpStream,
    mut addr: SocketAddr,
    key: &str,
    limiter: Limiter,
    ws: bool,
) -> ResultType<()> {
    if ws {
        use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};
        let callback = |req: &Request, response: Response| {
            let headers = req.headers();
            let real_ip = headers
                .get("X-Real-IP")
                .or_else(|| headers.get("X-Forwarded-For"))
                .and_then(|header_value| header_value.to_str().ok());
            if let Some(ip) = real_ip {
                if ip.contains('.') {
                    addr = format!("{ip}:0").parse().unwrap_or(addr);
                } else {
                    addr = format!("[{ip}]:0").parse().unwrap_or(addr);
                }
            }
            Ok(response)
        };
        let ws_stream = tokio_tungstenite::accept_hdr_async(stream, callback).await?;
        make_pair_(ws_stream, addr, key, limiter).await;
    } else {
        make_pair_(FramedStream::from(stream, addr), addr, key, limiter).await;
    }
    Ok(())
}

async fn make_pair_(stream: impl StreamTrait, addr: SocketAddr, key: &str, limiter: Limiter) {
    let mut stream = stream;
    if let Ok(Some(Ok(bytes))) = timeout(30_000, stream.recv()).await {
        if let Ok(msg_in) = RendezvousMessage::parse_from_bytes(&bytes) {
            if let Some(rendezvous_message::Union::RequestRelay(rf)) = msg_in.union {
                if !key.is_empty() && rf.licence_key != key {
                    return;
                }
                if !rf.uuid.is_empty() {
                    let mut peer = PEERS.remove(&rf.uuid).map(|(_, (_, v))| v);
                    if let Some(peer) = peer.as_mut() {
                        log::info!("Relayrequest {} from {} got paired", rf.uuid, addr);
                        let id = format!("{}:{}", addr.ip(), addr.port());
                        USAGE.insert(id.clone(), Default::default());
                        if !stream.is_ws() && !peer.is_ws() {
                            peer.set_raw();
                            stream.set_raw();
                            log::info!("Both are raw");
                        }
                        if let Err(err) = relay(addr, &mut stream, peer, limiter, id.clone()).await
                        {
                            log::info!("Relay of {} closed: {}", addr, err);
                        } else {
                            log::info!("Relay of {} closed", addr);
                        }
                        USAGE.remove(&id);
                    } else {
                        log::info!("New relay request {} from {}", rf.uuid, addr);
                        let insert_id = PEER_INSERT_COUNTER.fetch_add(1, Ordering::Relaxed);
                        PEERS.insert(rf.uuid.clone(), (insert_id, Box::new(stream)));
                        sleep(30.).await;
                        // Only remove our own entry; a newer insertion with the
                        // same uuid must not be accidentally evicted.
                        PEERS.remove_if(&rf.uuid, |_, (id, _)| *id == insert_id);
                    }
                }
            }
        }
    }
}

async fn relay(
    addr: SocketAddr,
    stream: &mut impl StreamTrait,
    peer: &mut Box<dyn StreamTrait>,
    total_limiter: Limiter,
    id: String,
) -> ResultType<()> {
    let ip = addr.ip().to_string();
    let mut tm = std::time::Instant::now();
    let mut elapsed: usize = 0;
    let mut total: usize = 0;
    let mut total_s: usize = 0;
    let mut highest_s: usize = 0;
    let mut downgrade: bool = false;
    let mut blacked: bool = false;
    let sb = SINGLE_BANDWIDTH.load(Ordering::Relaxed);
    let limiter = <Limiter>::new(sb as f64);
    let blacklist_limiter = <Limiter>::new(LIMIT_SPEED.load(Ordering::Relaxed) as _);
    // Integer math avoids float→int conversion: sb * threshold% / 100 / 1000 = sb * threshold% / 100_000
    let downgrade_threshold =
        (sb * DOWNGRADE_THRESHOLD_100.load(Ordering::Relaxed) / 100_000) as usize; // bit/ms
    // These rarely change at runtime — cache them per connection.
    let downgrade_start_check = DOWNGRADE_START_CHECK.load(Ordering::Relaxed);
    let mut last_recv_time = std::time::Instant::now();
    // Cache BLOCKLIST/BLACKLIST results for 5 s instead of checking every 1 s.
    let mut last_ip_check = std::time::Instant::now();
    // Existing relay session already initialised USAGE in make_pair_.
    // Use a 1 s tick for periodic accounting (statistics, timeout, block-list refresh)
    // instead of running Instant::elapsed() per-packet in the loop body.
    let mut stats_timer = interval(Duration::from_secs(1));
    loop {
        tokio::select! {
            // --- hot data path: peer → stream ---
            res = peer.recv() => {
                if let Some(Ok(bytes)) = res {
                    last_recv_time = std::time::Instant::now();
                    let nb = bytes.len() * 8;
                    if blacked || downgrade {
                        blacklist_limiter.consume(nb).await;
                    } else {
                        limiter.consume(nb).await;
                    }
                    total_limiter.consume(nb).await;
                    total += nb;
                    total_s += nb;
                    if !bytes.is_empty() {
                        stream.send_raw(bytes).await?;
                    }
                } else {
                    break;
                }
            },
            // --- hot data path: stream → peer ---
            res = stream.recv() => {
                if let Some(Ok(bytes)) = res {
                    last_recv_time = std::time::Instant::now();
                    let nb = bytes.len() * 8;
                    if blacked || downgrade {
                        blacklist_limiter.consume(nb).await;
                    } else {
                        limiter.consume(nb).await;
                    }
                    total_limiter.consume(nb).await;
                    total += nb;
                    total_s += nb;
                    if !bytes.is_empty() {
                        peer.send_raw(bytes).await?;
                    }
                } else {
                    break;
                }
            },
            // --- periodic accounting: runs every 1 s, not per-packet ---
            _ = stats_timer.tick() => {
                if last_recv_time.elapsed().as_secs() > 30 {
                    bail!("Timeout");
                }
                // Refresh block-list cache every 5 s to reduce DashSet lookups.
                if last_ip_check.elapsed().as_secs() >= 5 {
                    if BLOCKLIST.contains(&ip) {
                        log::info!("{} blocked", ip);
                        break;
                    }
                    blacked = BLACKLIST.contains(&ip);
                    last_ip_check = std::time::Instant::now();
                }
                if total_s == 0 {
                    tm = std::time::Instant::now();
                    continue;
                }
                let n = tm.elapsed().as_millis() as usize;
                let speed = total_s / n;
                if speed > highest_s {
                    highest_s = speed;
                }
                elapsed += n;
                // USAGE entry was already initialised in make_pair_ (line 454);
                // get_mut is the common path, and the fallback insert is dead code.
                if let Some(mut entry) = USAGE.get_mut(&id) {
                    *entry = (elapsed as _, total as _, highest_s as _, speed as _);
                }
                total_s = 0;
                tm = std::time::Instant::now();
                if elapsed > downgrade_start_check
                    && !downgrade
                    && total > elapsed * downgrade_threshold
                {
                    downgrade = true;
                    log::info!(
                        "Downgrade {}, exceed downgrade threshold {}bit/ms in {}ms",
                        id,
                        downgrade_threshold,
                        elapsed
                    );
                }
            }
        }
    }
    Ok(())
}

fn get_server_sk(key: &str) -> String {
    let mut key = key.to_owned();
    if let Ok(sk) = base64::decode(&key) {
        if sk.len() == sign::SECRETKEYBYTES {
            log::info!("The key is a crypto private key");
            key = base64::encode(&sk[(sign::SECRETKEYBYTES / 2)..]);
        }
    }

    if key == "-" || key == "_" {
        let (pk, _) = crate::common::gen_sk(300);
        key = pk;
    }

    if !key.is_empty() {
        log::info!("Key: {}", key);
    }

    key
}

#[async_trait]
trait StreamTrait: Send + Sync + 'static {
    // Returns Bytes (not BytesMut) to avoid an extra allocation on the WS recv path
    async fn recv(&mut self) -> Option<Result<Bytes, Error>>;
    async fn send_raw(&mut self, bytes: Bytes) -> ResultType<()>;
    fn is_ws(&self) -> bool;
    fn set_raw(&mut self);
}

#[async_trait]
impl StreamTrait for FramedStream {
    async fn recv(&mut self) -> Option<Result<Bytes, Error>> {
        // BytesMut::freeze() is zero-copy
        self.next().await.map(|r| r.map(|b| b.freeze()))
    }

    async fn send_raw(&mut self, bytes: Bytes) -> ResultType<()> {
        self.send_bytes(bytes).await
    }

    fn is_ws(&self) -> bool {
        false
    }

    fn set_raw(&mut self) {
        self.set_raw();
    }
}

#[async_trait]
impl StreamTrait for tokio_tungstenite::WebSocketStream<TcpStream> {
    async fn recv(&mut self) -> Option<Result<Bytes, Error>> {
        if let Some(msg) = self.next().await {
            match msg {
                Ok(msg) => {
                    match msg {
                        tungstenite::Message::Binary(bytes) => {
                            // Bytes::from(Vec) is zero-copy (takes ownership)
                            Some(Ok(Bytes::from(bytes)))
                        }
                        _ => Some(Ok(Bytes::new())),
                    }
                }
                Err(err) => Some(Err(Error::new(std::io::ErrorKind::Other, err.to_string()))),
            }
        } else {
            None
        }
    }

    async fn send_raw(&mut self, bytes: Bytes) -> ResultType<()> {
        // tungstenite 0.17 requires Vec<u8>; one copy is unavoidable here
        Ok(self
            .send(tungstenite::Message::Binary(bytes.to_vec()))
            .await?)
    }

    fn is_ws(&self) -> bool {
        true
    }

    fn set_raw(&mut self) {}
}
