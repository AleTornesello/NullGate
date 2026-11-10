//! NullGate process lifecycle. Web administration and TLS inspection are later milestones.
use nullgate_orchestrator::{
    AppConfig, Application, ProxyPhase, RuntimeError, RuntimePhase, RuntimeStatus,
};
use std::{path::PathBuf, process::ExitCode};
use tokio_util::sync::CancellationToken;

enum Action {
    Run(PathBuf),
    Provision {
        config: PathBuf,
        username: String,
        password_file: PathBuf,
    },
    Help,
    Version,
}
fn arguments() -> Result<Action, ()> {
    let mut args = std::env::args_os().skip(1);
    match args.next().as_deref() {
        Some(value) if value == "--help" || value == "-h" => {
            if args.next().is_none() {
                Ok(Action::Help)
            } else {
                Err(())
            }
        }
        Some(value) if value == "--version" => {
            if args.next().is_none() {
                Ok(Action::Version)
            } else {
                Err(())
            }
        }
        Some(value) if value == "provision-admin" => {
            let (mut config, mut username, mut password_file) = (None, None, None);
            while let Some(flag) = args.next() {
                let value = args.next().ok_or(())?;
                if flag == "--config" && config.is_none() {
                    config = Some(PathBuf::from(value));
                } else if flag == "--username" && username.is_none() {
                    username = Some(value.into_string().map_err(|_| ())?);
                } else if flag == "--password-file" && password_file.is_none() {
                    password_file = Some(PathBuf::from(value));
                } else {
                    return Err(());
                }
            }
            Ok(Action::Provision {
                config: config.ok_or(())?,
                username: username.ok_or(())?,
                password_file: password_file.ok_or(())?,
            })
        }
        Some(value) if value == "--config" => {
            let path = args.next().ok_or(())?;
            if args.next().is_some() {
                return Err(());
            }
            Ok(Action::Run(path.into()))
        }
        _ => Err(()),
    }
}
#[tokio::main]
async fn main() -> ExitCode {
    let (path, provision) = match arguments() {
        Ok(Action::Run(path)) => (path, None),
        Ok(Action::Provision {
            config,
            username,
            password_file,
        }) => (config, Some((username, password_file))),
        Ok(Action::Help) => {
            println!(
                "Usage: nullgate --config <path>\n       nullgate --help | --version\n       nullgate provision-admin --config <path> --username <name> --password-file <path>"
            );
            return ExitCode::SUCCESS;
        }
        Ok(Action::Version) => {
            println!("nullgate {}", env!("CARGO_PKG_VERSION"));
            return ExitCode::SUCCESS;
        }
        Err(()) => {
            eprintln!("Usage: nullgate --config <path>");
            return ExitCode::from(2);
        }
    };
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_ansi(false)
        .with_target(false)
        .with_writer(std::io::stderr)
        .init();
    let config = match AppConfig::load(&path) {
        Ok(config) => config,
        Err(error) => {
            tracing::error!(error=%error,"configuration rejected");
            return ExitCode::from(2);
        }
    };
    if let Some((username, password_file)) = provision {
        return match nullgate_orchestrator::provision_local_administrator(
            config,
            username,
            password_file,
        )
        .await
        {
            Ok(()) => {
                tracing::info!("administrator provisioned");
                ExitCode::SUCCESS
            }
            Err(error) => {
                tracing::error!(error=%error,"administrator provisioning failed");
                ExitCode::FAILURE
            }
        };
    }
    let cancel = CancellationToken::new();
    let signals = match signal_task(cancel.clone()) {
        Ok(signals) => signals,
        Err(_) => {
            tracing::error!(code = "signal_registration_failed", "startup failed");
            return ExitCode::FAILURE;
        }
    };
    tracing::info!(
        web_available = true,
        https_url_filtering = false,
        "starting proxy runtime"
    );
    let public_origin = config.web.public_origin.clone();
    let web_secure = config.web.tls.is_some() || config.web.tls_terminated_by_proxy;
    let app = match Application::start(config, cancel.clone()).await {
        Ok(app) => app,
        Err(RuntimeError::Cancelled) => {
            signals.abort();
            tracing::info!("runtime stopped");
            return ExitCode::SUCCESS;
        }
        Err(error) => {
            signals.abort();
            tracing::error!(error=%error,"startup failed");
            return ExitCode::FAILURE;
        }
    };
    let mut monitor = app.monitor();
    report(&monitor.current(), public_origin.as_deref(), web_secure);
    let wait = app.wait();
    tokio::pin!(wait);
    let result = loop {
        tokio::select! {
            biased;
            result=&mut wait=>break result,
            status=monitor.changed()=>{report(&status,public_origin.as_deref(),web_secure);if matches!(status.phase,RuntimePhase::Stopped|RuntimePhase::Failed){break wait.await;}}
        }
    };
    signals.abort();
    match result {
        Ok(()) => {
            tracing::info!("runtime stopped");
            ExitCode::SUCCESS
        }
        Err(error) => {
            tracing::error!(error=%error,"runtime failed");
            ExitCode::FAILURE
        }
    }
}
fn report(status: &RuntimeStatus, public_origin: Option<&str>, web_secure: bool) {
    if status.is_ready()
        && let (ProxyPhase::Ready(dns), ProxyPhase::Ready(http)) =
            (&status.dns.phase, &status.http.phase)
    {
        let udp = dns
            .listeners
            .iter()
            .find(|listener| listener.transport == nullgate_orchestrator::ServiceTransport::Udp);
        let tcp = dns
            .listeners
            .iter()
            .find(|listener| listener.transport == nullgate_orchestrator::ServiceTransport::Tcp);
        if let (Some(udp), Some(tcp), Some(http)) = (udp, tcp, http.listeners.first()) {
            if let Some(crate_web) = &status.web
                && let ProxyPhase::Ready(web) = &crate_web.phase
                && let Some(web) = web.listeners.first()
            {
                let origin = public_origin.map(str::to_owned).unwrap_or_else(|| {
                    format!(
                        "{}://{}",
                        if web_secure { "https" } else { "http" },
                        web.address
                    )
                });
                tracing::info!(dns_udp=%udp.address,dns_tcp=%tcp.address,http=%http.address,web=%web.address,web_origin=%origin,policy_revision=status.policy_revision,https_url_filtering=false,"runtime ready");
            }
            return;
        }
    }
    tracing::info!(ready=false,phase=?status.phase,dns=?status.dns,http=?status.http,web=?status.web,policy_unavailable=?status.policy_unavailable,"runtime health");
}
#[cfg(unix)]
fn signal_task(cancel: CancellationToken) -> std::io::Result<tokio::task::JoinHandle<()>> {
    use tokio::signal::unix::{SignalKind, signal};
    let mut terminate = signal(SignalKind::terminate())?;
    let mut interrupt = signal(SignalKind::interrupt())?;
    Ok(tokio::spawn(async move {
        tokio::select! {_=terminate.recv()=>{},_=interrupt.recv()=>{}}
        cancel.cancel();
    }))
}
#[cfg(not(unix))]
fn signal_task(cancel: CancellationToken) -> std::io::Result<tokio::task::JoinHandle<()>> {
    Ok(tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        cancel.cancel();
    }))
}
