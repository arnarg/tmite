use std::io::IsTerminal;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicI32, Ordering};

use anyhow::{Context, bail};
use clap::{Parser, Subcommand};
use tmite_core::client::connect::{ConnectParams, parse_fwd_spec};
use tmite_core::client::pair::{PairParams, PairUi};
use tmite_core::daemon::{DaemonConfig, run as daemon_run};
use tmite_core::fsio::{
    candidate_socket_paths, default_client_data_dir, default_socket_path, load_or_create_keypair,
};
use tmite_core::net::{NetOpts, grouped_hex};
use tokio::sync::{Notify, mpsc};

mod tui;

static EXIT_CODE: AtomicI32 = AtomicI32::new(0);

#[derive(Clone, Parser)]
#[command(
    name = "tmite",
    version,
    about = "Temporary forwarding tunnels over iroh"
)]
struct Cli {
    /// Verbosity: -v info, -vv trace (RUST_LOG also respected)
    #[arg(short = 'v', action = clap::ArgAction::Count, global = true)]
    verbose: u8,

    /// Override the data directory
    #[arg(long, global = true)]
    data_dir: Option<PathBuf>,

    /// Daemon IPC socket path (server commands)
    #[arg(long, global = true)]
    socket_path: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, Subcommand)]
enum Command {
    /// Run the daemon (server role)
    Daemon {
        /// Custom relay URL (repeatable; replaces the n0 relay map)
        #[arg(long = "relay")]
        relay: Vec<String>,
        /// Self-hosted pkarr relay for publishing and resolution
        #[arg(long)]
        pkarr: Option<String>,
        /// UDP port for the main tunnel endpoint (default: random)
        #[arg(long)]
        port: Option<u16>,
        /// Per-stream idle timeout in seconds (0 = disabled)
        #[arg(long, default_value_t = 0)]
        idle_timeout: u64,
    },
    /// Pair this client with a server using a spoken code
    Pair {
        /// The 5-word code (prompted if omitted)
        code: Option<String>,
        /// Skip interactive confirmation checks
        #[arg(long)]
        yes: bool,
        /// Local alias for the server (defaults to the server-chosen name)
        #[arg(long)]
        name: Option<String>,
    },
    /// Connect local listeners to a paired server
    Connect {
        /// Server alias from pairing
        name: String,
        /// Forward spec: [LOCAL_ADDR:]LOCAL_PORT:TARGET (repeatable)
        #[arg(long = "fwd")]
        fwd: Vec<String>,
        /// Disable the live TUI (paths, forwards, connections); implied
        /// when stdout is not a terminal
        #[arg(long)]
        no_tui: bool,
    },
    /// Print this node's iroh NodeId
    NodeId,
    /// Daemon admin commands (via the daemon's IPC socket)
    Admin {
        #[command(subcommand)]
        cmd: AdminCmd,
    },
}

#[derive(Clone, Subcommand)]
enum AdminCmd {
    /// Show daemon status
    Status,
    /// Manage peers, rules, and invites
    Peers {
        #[command(subcommand)]
        cmd: PeersCmd,
    },
    /// Manage ntfy push notifications (run on the daemon host)
    Ntfy {
        #[command(subcommand)]
        cmd: NtfyCmd,
    },
}

#[derive(Clone, Subcommand)]
enum NtfyCmd {
    /// Enable notifications with a fresh random topic
    Enable {
        /// Self-hosted ntfy server base URL (default: https://ntfy.sh)
        #[arg(long)]
        server: Option<String>,
    },
    /// Disable notifications (removes the topic)
    Disable,
    /// Print the notification topic
    Topic,
    /// Send a test notification to verify setup
    Test {
        /// Custom message body
        #[arg(long)]
        message: Option<String>,
    },
}

#[derive(Clone, Subcommand)]
enum PeersCmd {
    /// Create a pairing invite and wait for the admin's decision
    Invite {
        /// Peer name to register (becomes the ACL namespace)
        #[arg(long)]
        name: String,
        /// Invite TTL in seconds
        #[arg(long)]
        ttl: Option<u64>,
        /// Skip the y/N prompt for scripting (weakens the identity check)
        #[arg(long)]
        yes: bool,
    },
    /// Grant a peer access to one exact target
    Allow { peer: String, target: String },
    /// Remove one rule from a peer
    Revoke { peer: String, target: String },
    /// List peers, rules, and pending invites
    Ls,
    /// Delete a peer
    Rm {
        peer: String,
        /// Also delete the peer's rules
        #[arg(long)]
        force: bool,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    // In TUI mode the subscriber's stderr output would corrupt the inline
    // viewport; user-visible warnings reach the TUI via UiEvent::Notice.
    let tui_mode = match &cli.command {
        Command::Connect { no_tui, .. } => !*no_tui && std::io::stdout().is_terminal(),
        _ => false,
    };
    if !tui_mode {
        init_tracing(cli.verbose);
    }

    let result = match &cli.command {
        Command::Daemon {
            relay,
            pkarr,
            port,
            idle_timeout,
        } => {
            let data_dir = cli
                .data_dir
                .clone()
                .unwrap_or_else(|| PathBuf::from("/var/lib/tmite"));
            let socket_path = cli.socket_path.clone().unwrap_or_else(default_socket_path);
            daemon_run(DaemonConfig {
                data_dir,
                socket_path,
                idle_timeout: std::time::Duration::from_secs(*idle_timeout),
                net_opts: NetOpts {
                    relay_urls: relay.clone(),
                    pkarr_url: pkarr.clone(),
                    bind_port: *port,
                },
            })
            .await
            .map_err(anyhow::Error::from)
        }
        Command::Admin { cmd } => admin_cmd(cli.clone(), cmd.clone()).await,
        Command::Pair { code, name, .. } => pair_cmd(&cli, code.clone(), name.clone()).await,
        Command::Connect { name, fwd, no_tui } => {
            connect_cmd(&cli, name.clone(), fwd.clone(), *no_tui).await
        }
        Command::NodeId => node_id_cmd(&cli),
    };

    if let Err(e) = result {
        eprintln!("tmite: {e:#}");
        // Propagate a specific exit code if the inner layer set one.
        std::process::exit(EXIT_CODE.load(Ordering::SeqCst).max(1));
    }
}

fn init_tracing(verbose: u8) {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| match verbose {
        0 => EnvFilter::new("warn"),
        1 => EnvFilter::new("info"),
        _ => EnvFilter::new("trace"),
    });
    let _ = tracing_subscriber::fmt()
        .with_target(false)
        .event_format(tracing_subscriber::fmt::format::Format::default().compact())
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init();
}

fn client_data_dir(cli: &Cli) -> anyhow::Result<PathBuf> {
    match &cli.data_dir {
        Some(dir) => Ok(dir.clone()),
        None => Ok(default_client_data_dir()?),
    }
}

fn daemon_socket_candidates(cli: &Cli) -> Vec<PathBuf> {
    candidate_socket_paths(cli.socket_path.as_deref())
}

// ---------------------------------------------------------------------------
// IPC client (bin layer)
// ---------------------------------------------------------------------------

struct IpcConn {
    reader: tokio::io::BufReader<tokio::net::unix::OwnedReadHalf>,
    write: tokio::net::unix::OwnedWriteHalf,
}

async fn ipc_connect(paths: &[PathBuf]) -> anyhow::Result<IpcConn> {
    let mut last_err = None;
    for path in paths {
        match tokio::net::UnixStream::connect(path).await {
            Ok(stream) => {
                let (read, write) = stream.into_split();
                return Ok(IpcConn {
                    reader: tokio::io::BufReader::new(read),
                    write,
                });
            }
            Err(e) => {
                // A missing socket means this candidate simply isn't the one;
                // anything else is worth reporting if no candidate works.
                if e.kind() != std::io::ErrorKind::NotFound {
                    last_err = Some((path.clone(), anyhow::Error::new(e)));
                }
            }
        }
    }
    match last_err {
        Some((path, err)) => Err(err.context(format!(
            "cannot connect to daemon socket {}",
            path.display()
        ))),
        None => bail!(
            "daemon socket not found; tried: {}",
            paths
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

impl IpcConn {
    async fn send(&mut self, line: &str) -> anyhow::Result<()> {
        use tokio::io::AsyncWriteExt;
        self.write.write_all(line.as_bytes()).await?;
        self.write.write_all(b"\n").await?;
        self.write.flush().await?;
        Ok(())
    }

    async fn reply(&mut self) -> anyhow::Result<Option<tmite_proto::ipc::Reply>> {
        use tokio::io::AsyncBufReadExt;
        let mut line = String::new();
        let n = self.reader.read_line(&mut line).await?;
        if n == 0 {
            return Ok(None);
        }
        Ok(Some(serde_json::from_str(line.trim())?))
    }
}

fn ipc_request(id: u64, method: &str, params: serde_json::Value) -> String {
    serde_json::json!({ "id": id, "method": method, "params": params }).to_string()
}

async fn ipc_call(
    paths: &[PathBuf],
    method: &str,
    params: serde_json::Value,
) -> anyhow::Result<serde_json::Value> {
    let mut conn = ipc_connect(paths).await?;
    conn.send(&ipc_request(1, method, params)).await?;
    loop {
        let Some(reply) = conn.reply().await? else {
            bail!("daemon closed the IPC connection");
        };
        if reply.id != 1 {
            continue;
        }
        if let Some(err) = reply.error {
            bail!("daemon error [{}]: {}", err.code, err.message);
        }
        if let Some(result) = reply.result {
            return Ok(result);
        }
    }
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

async fn admin_cmd(cli: Cli, cmd: AdminCmd) -> anyhow::Result<()> {
    match cmd {
        AdminCmd::Status => status_cmd(&cli).await,
        AdminCmd::Peers { cmd } => peers_cmd(cli, cmd).await,
        AdminCmd::Ntfy { cmd } => ntfy_cmd(&cli, cmd).await,
    }
}

async fn peers_cmd(cli: Cli, cmd: PeersCmd) -> anyhow::Result<()> {
    let sockets = daemon_socket_candidates(&cli);
    match cmd {
        PeersCmd::Invite { name, ttl, yes } => invite_cmd(&sockets, name, ttl, yes).await,
        PeersCmd::Allow { peer, target } => {
            let result = ipc_call(
                &sockets,
                "peer.allow",
                serde_json::json!({ "peer": peer, "target": target }),
            )
            .await?;
            println!("rule added: {result}");
            Ok(())
        }
        PeersCmd::Revoke { peer, target } => {
            let result = ipc_call(
                &sockets,
                "peer.revoke",
                serde_json::json!({ "peer": peer, "target": target }),
            )
            .await?;
            let removed = result
                .get("removed")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            if removed {
                println!("rule removed");
            } else {
                println!("no such rule");
            }
            Ok(())
        }
        PeersCmd::Ls => {
            let result = ipc_call(&sockets, "peer.ls", serde_json::json!({})).await?;
            println!("{result:#}");
            Ok(())
        }
        PeersCmd::Rm { peer, force } => {
            let result = ipc_call(
                &sockets,
                "peer.rm",
                serde_json::json!({ "peer": peer, "force": force }),
            )
            .await?;
            let removed = result
                .get("removed")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            if removed {
                println!("peer {peer:?} removed");
            } else {
                println!("no such peer");
            }
            Ok(())
        }
    }
}

async fn invite_cmd(
    sockets: &[PathBuf],
    name: String,
    ttl: Option<u64>,
    yes: bool,
) -> anyhow::Result<()> {
    let mut conn = ipc_connect(sockets).await?;
    conn.send(&ipc_request(
        1,
        "peer.invite",
        serde_json::json!({ "name": name, "ttl": ttl }),
    ))
    .await?;

    let mut decided = false;
    let mut invite_id: Option<String> = None;
    loop {
        let Some(reply) = conn.reply().await? else {
            bail!("daemon closed the IPC connection");
        };
        if reply.id != 1 && reply.id != 2 {
            continue;
        }
        if let Some(err) = reply.error {
            bail!("daemon error [{}]: {}", err.code, err.message);
        }
        if let Some(event) = reply.event {
            match event.as_str() {
                "code" => {
                    let data = reply.data.unwrap_or(serde_json::Value::Null);
                    let code = data
                        .get("code")
                        .and_then(|c| c.as_str())
                        .unwrap_or("<unknown>");
                    let ttl_secs = data.get("ttl_secs").and_then(|t| t.as_u64()).unwrap_or(0);
                    invite_id = data
                        .get("invite_id")
                        .and_then(|i| i.as_str())
                        .map(str::to_string);
                    println!("Invite code (valid for {ttl_secs}s):");
                    println!("  {code}");
                    println!("Read this code to the client operator.");
                }
                "pair_request" => {
                    let data = reply.data.unwrap_or(serde_json::Value::Null);
                    let node_id = data
                        .get("node_id")
                        .and_then(|n| n.as_str())
                        .unwrap_or("<unknown>")
                        .to_string();
                    println!("Pairing request from client:");
                    println!("  {}", grouped_node_id(&node_id));
                    let accept = yes || prompt_y_n()?;
                    let invite_id = data
                        .get("invite_id")
                        .and_then(|i| i.as_str())
                        .map(str::to_string)
                        .or_else(|| invite_id.clone())
                        .unwrap_or_default();
                    conn.send(&ipc_request(
                        2,
                        "peer.invite.decide",
                        serde_json::json!({
                            "invite_id": invite_id,
                            "accept": accept
                        }),
                    ))
                    .await?;
                    decided = true;
                }
                "expired" if !decided && !yes => {
                    println!("Invite expired.");
                }
                "cancelled" => bail!("invite cancelled"),
                _ => {}
            }
        }
        if let Some(result) = reply.result {
            if reply.id != 1 {
                continue;
            }
            let status = result.get("status").and_then(|s| s.as_str()).unwrap_or("");
            match status {
                "paired" => {
                    let node_id = result
                        .get("node_id")
                        .and_then(|n| n.as_str())
                        .unwrap_or("<unknown>");
                    println!("Paired. Peer registered as:");
                    println!("  {node_id}");
                    return Ok(());
                }
                "rejected" => {
                    println!("Invite rejected; the code is now dead.");
                    return Ok(());
                }
                "expired" => {
                    println!("Invite expired without a pairing.");
                    return Ok(());
                }
                _ => bail!("unexpected result: {result}"),
            }
        }
    }
}

fn prompt_y_n() -> anyhow::Result<bool> {
    // Read from /dev/tty so piped input cannot auto-confirm (§9.3).
    let tty = std::fs::File::open("/dev/tty")
        .context("no TTY available for confirmation; pass --yes for scripting")?;
    let term = console::Term::read_write_pair(tty, std::io::stderr());
    let accept = dialoguer::Confirm::new()
        .with_prompt("Pair this client?")
        .default(false)
        .wait_for_newline(true)
        .interact_on(&term)?;
    Ok(accept)
}

fn grouped_node_id(node_id: &str) -> String {
    let bytes: Vec<u8> = (0..node_id.len())
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(&node_id[i..i + 2], 16).ok())
        .collect();
    grouped_hex(&bytes)
}

async fn status_cmd(cli: &Cli) -> anyhow::Result<()> {
    let result = ipc_call(
        &daemon_socket_candidates(cli),
        "daemon.sessions",
        serde_json::json!({}),
    )
    .await?;
    let result: tmite_proto::ipc::SessionsResult = serde_json::from_value(result)?;
    print_sessions_table(&result);
    Ok(())
}

/// One display row per peer; PROXIES and STATE may span multiple lines.
struct StatusRow {
    name: String,
    node_id: String,
    proxies: Vec<String>,
    state: Vec<String>,
}

fn print_sessions_table(result: &tmite_proto::ipc::SessionsResult) {
    let rows: Vec<StatusRow> = result
        .peers
        .iter()
        .map(|p| {
            let session = p.session.as_ref();
            let proxies: Vec<String> = match session {
                Some(s) if !s.forwards.is_empty() => s
                    .forwards
                    .iter()
                    .map(|f| {
                        if f.live > 0 {
                            format!("{} \u{2192} {} ({})", f.local, f.target, f.live)
                        } else {
                            format!("{} \u{2192} {}", f.local, f.target)
                        }
                    })
                    .collect(),
                _ => vec!["-".to_string()],
            };
            let state: Vec<String> = match session {
                Some(s) if !s.paths.is_empty() => s
                    .paths
                    .iter()
                    .map(|path| {
                        let kind = match path.kind {
                            tmite_proto::ipc::PathKind::Direct => "direct".to_string(),
                            tmite_proto::ipc::PathKind::Relay => "relay".to_string(),
                        };
                        let addr = match (&path.kind, &path.addr) {
                            (tmite_proto::ipc::PathKind::Direct, Some(addr)) => {
                                format!(" {addr}")
                            }
                            _ => String::new(),
                        };
                        let rtt = path
                            .rtt_ms
                            .map(|ms| format!(" ({ms}ms)"))
                            .unwrap_or_default();
                        let mark = if path.selected {
                            "\u{25cf}"
                        } else {
                            "\u{25cb}"
                        };
                        format!("{mark} {kind}{addr}{rtt}")
                    })
                    .collect(),
                _ => vec!["-".to_string()],
            };
            StatusRow {
                name: p.name.clone(),
                node_id: short_node_id(&p.node_id),
                proxies,
                state,
            }
        })
        .collect();

    if rows.is_empty() {
        println!("no peers paired");
        return;
    }

    let name_w = rows
        .iter()
        .map(|r| r.name.chars().count())
        .chain(std::iter::once("NAME".len()))
        .max()
        .unwrap_or(0);
    let node_w = rows
        .iter()
        .map(|r| r.node_id.chars().count())
        .chain(std::iter::once("NODE ID".len()))
        .max()
        .unwrap_or(0);
    let proxy_w = rows
        .iter()
        .flat_map(|r| &r.proxies)
        .map(|l| l.chars().count())
        .chain(std::iter::once("PROXIES".len()))
        .max()
        .unwrap_or(0);

    println!(
        "{:<name_w$}  {:<node_w$}  {:<proxy_w$}  STATE",
        "NAME", "NODE ID", "PROXIES"
    );
    for row in &rows {
        let lines = row.proxies.len().max(row.state.len());
        for i in 0..lines {
            let name = if i == 0 { &row.name } else { "" };
            let node_id = if i == 0 { &row.node_id } else { "" };
            let proxy = line_or_dash(&row.proxies, i);
            let state = line_or_dash(&row.state, i);
            println!(
                "{:<name_w$}  {:<node_w$}  {:<proxy_w$}  {}",
                name,
                node_id,
                pad(proxy, proxy_w),
                state
            );
        }
    }
}

fn line_or_dash(lines: &[String], index: usize) -> &str {
    lines.get(index).map(String::as_str).unwrap_or("")
}

fn pad(text: &str, width: usize) -> String {
    let len = text.chars().count();
    if len >= width {
        text.to_string()
    } else {
        format!("{text}{}", " ".repeat(width - len))
    }
}

/// First 8 hex chars plus an ellipsis, enough to spot the peer in `peer ls`.
fn short_node_id(node_id: &str) -> String {
    let mut short = node_id.chars().take(8).collect::<String>();
    if node_id.chars().count() > 8 {
        short.push('\u{2026}');
    }
    short
}

struct PairPromptUi;

impl PairUi for PairPromptUi {
    fn info(&self, msg: &str) {
        println!("{msg}");
    }
    fn show_node_id(&self, id: &iroh::PublicKey) {
        println!("This client's NodeId:");
        println!("  {}", grouped_hex(&id.as_bytes()[..]));
    }
    fn paired(&self, name: &str, server_id: &iroh::PublicKey) {
        println!("Paired as {name:?} on:");
        println!("  {}", grouped_hex(&server_id.as_bytes()[..]));
    }
}

async fn pair_cmd(cli: &Cli, code: Option<String>, name: Option<String>) -> anyhow::Result<()> {
    let name = name.map(|n| n.trim().to_string()).filter(|n| !n.is_empty());
    let mut code_opt = code;
    let mut attempts = 0;
    loop {
        if code_opt.is_none() {
            code_opt = Some(prompt_code()?);
        }
        let code = code_opt.clone().unwrap();
        match tmite_proto::pairing::code_to_entropy(&code) {
            Ok(_) => {
                code_opt = Some(code);
                break;
            }
            Err(e) => {
                attempts += 1;
                if attempts >= tmite_proto::limits::PAIR_MAX_ATTEMPTS {
                    EXIT_CODE.store(2, Ordering::SeqCst);
                    bail!("invalid code: {e}");
                }
                eprintln!(
                    "tmite: {e}; try again ({}/{} attempts left)",
                    tmite_proto::limits::PAIR_MAX_ATTEMPTS - attempts,
                    tmite_proto::limits::PAIR_MAX_ATTEMPTS
                );
                code_opt = None;
            }
        }
    }
    let code = code_opt.unwrap();

    let params = PairParams {
        code,
        data_dir: client_data_dir(cli)?,
        client_version: tmite_core::CRATE_VERSION.to_string(),
        net_opts: NetOpts::default(),
        name,
    };
    let ui = PairPromptUi;
    match tmite_core::client::pair::run(params, &ui).await {
        Ok(_) => Ok(()),
        Err(e) => {
            EXIT_CODE.store(e.exit_code(), Ordering::SeqCst);
            bail!("{e}");
        }
    }
}

fn prompt_code() -> anyhow::Result<String> {
    let code: String = dialoguer::Input::new()
        .with_prompt("Enter the pairing code")
        .interact_text()?;
    Ok(code.trim().to_string())
}

async fn connect_cmd(
    cli: &Cli,
    name: String,
    fwd: Vec<String>,
    no_tui: bool,
) -> anyhow::Result<()> {
    if fwd.is_empty() {
        bail!("at least one --fwd spec is required");
    }
    let mut specs = Vec::new();
    for spec in fwd {
        specs.push(parse_fwd_spec(&spec)?);
    }
    let shutdown = Arc::new(Notify::new());
    let base = ConnectParams {
        name: name.clone(),
        specs: specs.clone(),
        data_dir: client_data_dir(cli)?,
        net_opts: NetOpts::default(),
        events: None,
        shutdown: shutdown.clone(),
    };
    let use_tui = !no_tui && std::io::stdout().is_terminal();
    if use_tui {
        let (tx, rx) = mpsc::unbounded_channel();
        let params = ConnectParams {
            events: Some(tx),
            ..base
        };
        let n_forwards = params.specs.len();
        let tui_task = tokio::spawn(tui::run(rx, shutdown.clone(), n_forwards));
        let result = tmite_core::client::connect::run(params).await;
        // Wait for the terminal to be restored before reporting errors.
        let _ = tui_task.await;
        result.map_err(anyhow::Error::from)
    } else {
        println!("Connecting to {name}...");
        tmite_core::client::connect::run(base)
            .await
            .map_err(anyhow::Error::from)
    }
}

fn node_id_cmd(cli: &Cli) -> anyhow::Result<()> {
    let data_dir = client_data_dir(cli)?;
    let keypair = load_or_create_keypair(&data_dir.join("keypair"))?;
    let id = keypair.public();
    println!("{}", grouped_hex(&id.as_bytes()[..]));
    Ok(())
}

// ---------------------------------------------------------------------------
// ntfy notifications (management goes through the daemon's IPC; §18)
// ---------------------------------------------------------------------------

async fn ntfy_cmd(cli: &Cli, cmd: NtfyCmd) -> anyhow::Result<()> {
    let sockets = daemon_socket_candidates(cli);
    match cmd {
        NtfyCmd::Enable { server } => {
            let result = ipc_call(
                &sockets,
                "ntfy.enable",
                serde_json::json!({ "server": server }),
            )
            .await?;
            println!("ntfy topic created:");
            println!(
                "  {}/{}",
                result["server_url"].as_str().unwrap_or(""),
                result["topic"].as_str().unwrap_or("")
            );
            println!("Subscribe to this topic to receive notifications.");
            println!("Takes effect immediately; no daemon restart needed.");
        }
        NtfyCmd::Disable => {
            let result = ipc_call(&sockets, "ntfy.disable", serde_json::json!({})).await?;
            if result["removed"].as_bool().unwrap_or(false) {
                println!("ntfy notifications disabled");
            } else {
                println!("ntfy notifications were not enabled");
            }
        }
        NtfyCmd::Topic => {
            let result = ipc_call(&sockets, "ntfy.status", serde_json::json!({})).await?;
            if !result["enabled"].as_bool().unwrap_or(false) {
                bail!("ntfy notifications are disabled; run `tmite admin ntfy enable` first");
            }
            println!("{}", result["topic"].as_str().unwrap_or_default());
        }
        NtfyCmd::Test { message } => {
            ipc_call(
                &sockets,
                "ntfy.test",
                serde_json::json!({ "message": message }),
            )
            .await?;
            println!("test notification sent");
        }
    }
    Ok(())
}
