use std::process::ExitCode;

#[cfg(target_os = "linux")]
fn main() -> ExitCode {
    use yonik_linux::{
        Cancellation,
        helper::{
            SystemSessionHost, fence::verify_worker_fence, launch_standalone_sandbox,
            launch_standalone_worker, run_system_service, standalone_sandbox_argument,
            standalone_worker_argument,
        },
        worker::WorkerMode,
    };
    let mut args = std::env::args_os().skip(1);
    let mut standalone = false;
    if let Some(argument) = args.next() {
        if args.next().is_some() {
            return ExitCode::from(64);
        }
        if (argument == "--standalone-service" && standalone_service_init())
            || (argument == "--standalone-test-service" && standalone_test_vm())
        {
            standalone = true;
        } else if argument == "--check-worker-fence" {
            return if verify_worker_fence().is_ok() {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            };
        } else if let Some(result) =
            [WorkerMode::Check, WorkerMode::Run]
                .into_iter()
                .find_map(|mode| {
                    if argument == standalone_worker_argument(mode) {
                        Some(launch_standalone_worker(mode))
                    } else if argument == standalone_sandbox_argument(mode) {
                        Some(launch_standalone_sandbox(mode))
                    } else {
                        None
                    }
                })
        {
            return match result {
                Ok(never) => match never {},
                Err(error) => {
                    eprintln!("{error}");
                    ExitCode::FAILURE
                }
            };
        } else {
            return ExitCode::from(64);
        }
    }
    if rustix::process::geteuid().as_raw() != 0 {
        return ExitCode::from(77);
    }
    if !standalone && verify_worker_fence().is_err() {
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
        let host = if standalone {
            SystemSessionHost::system_standalone(cancel.clone()).await
        } else {
            SystemSessionHost::system(cancel.clone()).await
        };
        let result = match host {
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

#[cfg(target_os = "linux")]
fn standalone_service_init() -> bool {
    std::fs::read_to_string("/proc/1/comm").is_ok_and(|init| !matches!(init.trim(), "" | "systemd"))
}

#[cfg(target_os = "linux")]
fn standalone_test_vm() -> bool {
    cfg!(feature = "test-support")
        && std::env::var("YONIK_PRODUCTION_HELPER_VM").as_deref() == Ok("1")
        && std::fs::read_to_string("/sys/class/dmi/id/sys_vendor")
            .is_ok_and(|vendor| vendor.trim() == "QEMU")
        && std::fs::read_to_string("/etc/yonik-production-helper-vm")
            .as_deref()
            .is_ok_and(|marker| marker == "yonik-production-helper-disposable-v1\n")
}
#[cfg(not(target_os = "linux"))]
fn main() -> ExitCode {
    ExitCode::from(69)
}
