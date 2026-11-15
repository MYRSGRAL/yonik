//! Fixed SIGKILL при потере родителя локального sealed core; не worker API.
// Target guard не доказывает backend: требуется отдельный exact-build receipt.
#[cfg(not(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64",
    target_env = "gnu"
)))]
compile_error!("local parent-death: требуется verified x86_64-unknown-linux-gnu/raw backend");

use rustix::process::{Signal, getpid, getppid, set_parent_process_death_signal};
use std::{io, os::unix::process::CommandExt, process::Command};

pub const LOCAL_PROFILE_LOCATORS: [&str; 4] = [
    "YONIK_PROFILE_CONTROL_FD",
    "YONIK_PROFILE_LAUNCH_FD",
    "YONIK_PROFILE_PEER_PIDFD",
    "YONIK_PROFILE_ASSET_ROOT_FD",
];

trait FdOps: Send + Sync + 'static {
    fn get(&self, fd: i32) -> io::Result<i32>;
    fn set(&self, fd: i32, flags: i32) -> io::Result<()>;
}
trait HookSink {
    fn configured(&self) -> bool;
    fn locator(&mut self, name: &'static str, fd: i32);
    fn hook(&mut self, hook: impl FnMut() -> io::Result<()> + Send + Sync + 'static);
}
fn install_with<F: std::os::fd::AsRawFd + Send + Sync + 'static>(
    sink: &mut impl HookSink,
    fds: [F; 4],
    ops: impl FdOps,
) -> io::Result<()> {
    if sink.configured() {
        return Err(io::Error::from_raw_os_error(libc::EALREADY));
    }
    let numbers = fds.each_ref().map(|fd| fd.as_raw_fd());
    for (index, fd) in numbers.iter().enumerate() {
        if *fd < 3 || numbers[..index].contains(fd) || ops.get(*fd)? & libc::FD_CLOEXEC == 0 {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }
    }
    for (name, fd) in LOCAL_PROFILE_LOCATORS.into_iter().zip(numbers) {
        sink.locator(name, fd);
    }
    sink.hook(move || {
        // Capture содержит сами owned handles, а не только их номера.
        run_child(&ops, fds.each_ref().map(|fd| fd.as_raw_fd()))
    });
    Ok(())
}
fn run_child(ops: &impl FdOps, numbers: [i32; 4]) -> io::Result<()> {
    for fd in numbers {
        let flags = ops.get(fd)?;
        ops.set(fd, flags & !libc::FD_CLOEXEC)?;
    }
    Ok(())
}
struct RawFdOps;
impl FdOps for RawFdOps {
    #[allow(unsafe_code)]
    fn get(&self, fd: i32) -> io::Result<i32> {
        // SAFETY: raw fcntl GETFD не использует pointers/allocator/locks.
        let result = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if result == -1 {
            Err(raw_errno())
        } else {
            Ok(result)
        }
    }
    #[allow(unsafe_code)]
    fn set(&self, fd: i32, flags: i32) -> io::Result<()> {
        // SAFETY: raw fcntl SETFD принимает только Copy integers.
        if unsafe { libc::fcntl(fd, libc::F_SETFD, flags) } == -1 {
            Err(raw_errno())
        } else {
            Ok(())
        }
    }
}
#[allow(unsafe_code)]
fn raw_errno() -> io::Error {
    // SAFETY: errno TLS текущего потока, без formatting/allocation.
    io::Error::from_raw_os_error(unsafe { *libc::__errno_location() })
}
impl HookSink for Command {
    fn configured(&self) -> bool {
        self.get_envs()
            .any(|(name, _)| LOCAL_PROFILE_LOCATORS.iter().any(|key| name == *key))
    }
    fn locator(&mut self, name: &'static str, fd: i32) {
        self.env(name, fd.to_string());
    }
    #[allow(unsafe_code)]
    fn hook(&mut self, hook: impl FnMut() -> io::Result<()> + Send + Sync + 'static) {
        // SAFETY: единственный production callback — run_child<RawFdOps>.
        // После fork он использует только четыре owned FD, Copy flags,
        // raw GETFD/SETFD и errno-only Error. Drop handles остаётся у Command.
        unsafe {
            self.pre_exec(hook);
        }
    }
}
/// Только fresh Local BinarySnapshot command с уже установленным fixed
/// parent-death hook. Не снимает CLOEXEC в родителе, не заменяет существующие
/// hooks. Повторная настройка Command с locators отвергается до mutation;
/// caller также удерживает one-shot configure state, включая env_clear reuse.
pub fn install_local_profile_fds(
    command: &mut Command,
    fds: [std::os::fd::OwnedFd; 4],
) -> io::Result<()> {
    install_with(command, fds, RawFdOps)
}

/// Устанавливается только на command локального sealed BinarySnapshot.
/// PID захватывается внутри; caller не задаёт signal, PID или syscall arguments.
#[allow(unsafe_code)]
pub fn install_kill_on_parent_death(command: &mut Command) {
    let expected_parent = getpid();
    // SAFETY: после fork closure использует только getppid/prctl raw wrappers,
    // Copy PID и errno-only io::Error. Нет allocator, locks, logging, env,
    // доступа к унаследованным library state/FD. Proof условен: rustix 1.1.6
    // linux_raw, LP64 и штатный getppid без errno emulation; dependency debug
    // unwrap/assert существуют, но недостижимы при этом предусловии.
    // Иной backend/ABI или неизвестная getppid sandbox policy не поддержаны.
    // SIGKILL фиксирован; несовпадение родителя/ошибка запрещают exec.
    unsafe {
        command.pre_exec(move || {
            if getppid() != Some(expected_parent) {
                return Err(io::Error::from_raw_os_error(
                    rustix::io::Errno::SRCH.raw_os_error(),
                ));
            }
            set_parent_process_death_signal(Some(Signal::KILL))
                .map_err(|error| io::Error::from_raw_os_error(error.raw_os_error()))?;
            if getppid() != Some(expected_parent) {
                return Err(io::Error::from_raw_os_error(
                    rustix::io::Errno::SRCH.raw_os_error(),
                ));
            }
            Ok(())
        });
    }
}

#[cfg(test)]
mod profile_fd_tests {
    use super::*;
    use std::{
        collections::BTreeMap,
        os::fd::AsRawFd,
        sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
        },
    };
    type Hook = Box<dyn FnMut() -> io::Result<()> + Send + Sync>;
    #[derive(Default)]
    struct Sink {
        locators: BTreeMap<&'static str, i32>,
        hooks: Vec<Hook>,
    }
    impl HookSink for Sink {
        fn configured(&self) -> bool {
            !self.locators.is_empty()
        }
        fn locator(&mut self, name: &'static str, fd: i32) {
            self.locators.insert(name, fd);
        }
        fn hook(&mut self, hook: impl FnMut() -> io::Result<()> + Send + Sync + 'static) {
            self.hooks.push(Box::new(hook));
        }
    }
    struct Fd {
        number: i32,
        dropped: Arc<AtomicUsize>,
    }
    impl AsRawFd for Fd {
        fn as_raw_fd(&self) -> i32 {
            self.number
        }
    }
    impl Drop for Fd {
        fn drop(&mut self) {
            self.dropped.fetch_add(1, Ordering::SeqCst);
        }
    }
    #[derive(Clone, Default)]
    struct Ops {
        events: Arc<Mutex<Vec<(i32, i32)>>>,
        failure: i32,
    }
    impl FdOps for Ops {
        fn get(&self, fd: i32) -> io::Result<i32> {
            self.events.lock().unwrap().push((fd, -1));
            if self.failure == fd {
                Err(io::Error::from_raw_os_error(libc::EBADF))
            } else {
                Ok(libc::FD_CLOEXEC | 8)
            }
        }
        fn set(&self, fd: i32, flags: i32) -> io::Result<()> {
            self.events.lock().unwrap().push((fd, flags));
            if self.failure == -fd {
                Err(io::Error::from_raw_os_error(libc::EIO))
            } else {
                Ok(())
            }
        }
    }
    fn fds(dropped: &Arc<AtomicUsize>) -> [Fd; 4] {
        std::array::from_fn(|i| Fd {
            number: 20 + i as i32,
            dropped: Arc::clone(dropped),
        })
    }
    #[test]
    fn four_owned_fds_survive_until_command_drop_and_parent_flags_are_never_written() {
        let dropped = Arc::new(AtomicUsize::new(0));
        let ops = Ops::default();
        let mut sink = Sink::default();
        install_with(&mut sink, fds(&dropped), ops.clone()).unwrap();
        assert_eq!(dropped.load(Ordering::SeqCst), 0);
        assert_eq!(sink.hooks.len(), 1);
        assert!(
            ops.events
                .lock()
                .unwrap()
                .iter()
                .all(|(_, flags)| *flags == -1)
        );
        assert_eq!(
            sink.locators.values().copied().collect::<Vec<_>>(),
            vec![23, 20, 21, 22]
        );
        ops.events.lock().unwrap().clear();
        sink.hooks[0]().unwrap();
        assert_eq!(
            *ops.events.lock().unwrap(),
            vec![
                (20, -1),
                (20, 8),
                (21, -1),
                (21, 8),
                (22, -1),
                (22, 8),
                (23, -1),
                (23, 8)
            ]
        );
        drop(sink);
        assert_eq!(dropped.load(Ordering::SeqCst), 4);
    }
    #[test]
    fn command_reconfiguration_does_not_append_hooks_or_replace_locators() {
        let dropped = Arc::new(AtomicUsize::new(0));
        let mut sink = Sink::default();
        install_with(&mut sink, fds(&dropped), Ops::default()).unwrap();
        let before = sink.locators.clone();
        assert!(install_with(&mut sink, fds(&dropped), Ops::default()).is_err());
        assert_eq!(sink.hooks.len(), 1);
        assert_eq!(sink.locators, before);
        assert_eq!(dropped.load(Ordering::SeqCst), 4);
        drop(sink);
        assert_eq!(dropped.load(Ordering::SeqCst), 8);
    }
    #[test]
    fn parent_preflight_error_or_invalid_alias_adds_no_hook_or_locator() {
        for case in 0..3 {
            let dropped = Arc::new(AtomicUsize::new(0));
            let mut sink = Sink::default();
            let mut handles = fds(&dropped);
            let mut ops = Ops::default();
            match case {
                0 => handles[0].number = 2,
                1 => handles[3].number = 20,
                _ => ops.failure = 22,
            }
            assert!(install_with(&mut sink, handles, ops).is_err());
            assert!(sink.locators.is_empty());
            assert!(sink.hooks.is_empty());
            assert_eq!(dropped.load(Ordering::SeqCst), 4);
        }
    }
    #[test]
    fn existing_parent_death_hook_runs_first_and_failure_prevents_fd_mutation() {
        let dropped = Arc::new(AtomicUsize::new(0));
        let ops = Ops::default();
        let mut sink = Sink::default();
        sink.hook(|| Err(io::Error::from_raw_os_error(libc::ESRCH)));
        install_with(&mut sink, fds(&dropped), ops.clone()).unwrap();
        ops.events.lock().unwrap().clear();
        let result = sink.hooks.iter_mut().try_for_each(|hook| hook());
        assert_eq!(result.unwrap_err().raw_os_error(), Some(libc::ESRCH));
        assert!(ops.events.lock().unwrap().is_empty());
    }
    #[test]
    fn child_getfd_or_setfd_error_stops_before_any_later_descriptor() {
        for failure in [22, -22] {
            let dropped = Arc::new(AtomicUsize::new(0));
            let ops = Ops::default();
            let mut sink = Sink::default();
            install_with(&mut sink, fds(&dropped), ops.clone()).unwrap();
            // Ошибка появляется только после fork, parent preflight успешен.
            let failing = Ops {
                failure,
                ..ops.clone()
            };
            ops.events.lock().unwrap().clear();
            assert!(run_child(&failing, [20, 21, 22, 23]).is_err());
            assert!(!ops.events.lock().unwrap().iter().any(|(fd, _)| *fd == 23));
        }
    }
}
