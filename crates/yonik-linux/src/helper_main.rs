use std::process::ExitCode;

#[cfg(target_os = "linux")]
fn main() -> ExitCode {
    use yonik_linux::{
        Cancellation,
        helper::{
            SystemSessionHost, fence::verify_worker_fence, launch_standalone_worker,
            run_system_service, standalone_worker_argument,
        },
        worker::WorkerMode,
    };
    let mut args = std::env::args_os().skip(1);
    if let Some(argument) = args.next() {
        if args.next().is_some() {
            return ExitCode::from(64);
        }
        return if argument == "--check-worker-fence" {
            if verify_worker_fence().is_ok() {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        } else if let Some(mode) = [WorkerMode::Check, WorkerMode::Run]
            .into_iter()
            .find(|&mode| argument == standalone_worker_argument(mode))
        {
            match launch_standalone_worker(mode) {
                Ok(never) => match never {},
                Err(error) => {
                    eprintln!("{error}");
                    ExitCode::FAILURE
                }
            }
        } else {
            ExitCode::from(64)
        };
    }
    if rustix::process::geteuid().as_raw() != 0 {
        return ExitCode::from(77);
    }
    if verify_worker_fence().is_err() {
        return ExitCode::from(75);
    }
    let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        return ExitCode::from(70);
    };
    runtime.block_on(async {
        let (signal, cancel) = Cancellation::new();
        let stop = tokio::spawn(async move {
            let Ok(mut term) =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            else {
                return;
            };
            tokio::select! {_ = tokio::signal::ctrl_c()=>{},_ = term.recv()=>{}}
            signal.send_replace(true);
        });
        let result = match SystemSessionHost::system(cancel.clone()).await {
            Ok(host) => run_system_service(host, cancel).await,
            Err(error) => Err(error),
        };
        stop.abort();
        let _stopped = stop.await;
        if result.is_ok() {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(69)
        }
    })
}
#[cfg(not(target_os = "linux"))]
fn main() -> ExitCode {
    ExitCode::from(69)
}
