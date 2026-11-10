//! NullGate process lifecycle. Web administration and TLS inspection are later milestones.
use nullgate_orchestrator::{
    AppConfig, Application, ProxyPhase, RuntimeError, RuntimePhase, RuntimeStatus,
};
use std::{path::PathBuf, process::ExitCode};
use tokio_util::sync::CancellationToken;

enum Action {
    Run(PathBuf),
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
    let path = match arguments() {
        Ok(Action::Run(path)) => path,
        Ok(Action::Help) => {
            println!("Usage: nullgate --config <path>\n       nullgate --help | --version");
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
    let cancel = CancellationToken::new();
    let signals = match signal_task(cancel.clone()) {
        Ok(signals) => signals,
        Err(_) => {
            tracing::error!(code = "signal_registration_failed", "startup failed");
            return ExitCode::FAILURE;
        }
    };
    tracing::info!(
        web_available = false,
        https_url_filtering = false,
        "starting proxy runtime"
    );
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
    report(&monitor.current());
    let wait = app.wait();
    tokio::pin!(wait);
    let result = loop {
        tokio::select! {
            biased;
            result=&mut wait=>break result,
            status=monitor.changed()=>{report(&status);if matches!(status.phase,RuntimePhase::Stopped|RuntimePhase::Failed){break wait.await;}}
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
fn report(status: &RuntimeStatus) {
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
            tracing::info!(dns_udp=%udp.address,dns_tcp=%tcp.address,http=%http.address,policy_revision=status.policy_revision,https_url_filtering=false,"runtime ready");
            return;
        }
    }
    tracing::info!(ready=false,phase=?status.phase,dns=?status.dns,http=?status.http,policy_unavailable=?status.policy_unavailable,"runtime health");
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
