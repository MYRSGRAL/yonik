use super::*;

#[test]
fn streaming_config_bounds_hash_and_seals_the_only_plaintext_copy() {
    let mut writer = BoundedConfig::new().unwrap();
    let chunk = [b'x'; 8192];
    for _ in 0..MAX_ARTIFACT_BYTES / chunk.len() {
        writer.write_all(&chunk).unwrap();
    }
    assert!(writer.write_all(b"extra").is_err());
    let (file, length, hash) = writer.finish().unwrap();
    assert_eq!(length, MAX_ARTIFACT_BYTES);
    validate_file(&file, length, hash).unwrap();
    assert_eq!(file.metadata().unwrap().len(), MAX_ARTIFACT_BYTES as u64);
}
#[test]
fn header_rejects_every_truncation_and_unknown_discriminants() {
    let valid = Header {
        mode: WorkerMode::Check,
        engine: Engine::Xray,
        length: 12,
        binary_hash: [3; 32],
        config_hash: [7; 32],
    }
    .encode();
    for end in 0..valid.len() {
        assert!(Header::decode(&valid[..end]).is_err());
    }
    assert_eq!(Header::decode(&valid).unwrap().length, 12);
    for index in [0, 7, 8, 9, 10, 11] {
        let mut changed = valid;
        changed[index] = 255;
        assert!(Header::decode(&changed).is_err());
    }
    let mut zero = valid;
    zero[12..16].copy_from_slice(&0u32.to_be_bytes());
    assert!(Header::decode(&zero).is_err());
}
#[test]
fn unsealed_and_bad_hash_descriptors_are_rejected() {
    let file = File::from(
        memfd_create("invalid", MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING).unwrap(),
    );
    assert_eq!(
        validate_file(&file, 4, [0; 32]).err(),
        Some(WorkerError::Protocol)
    );
    let file = sealed_config(b"safe").unwrap();
    assert_eq!(
        validate_file(&file, 4, [0; 32]).err(),
        Some(WorkerError::Protocol)
    );
    assert!(validate_file(&file, 4, Hasher::digest(b"safe").into()).is_ok());
}

fn send_request(stream: &UnixStream, bytes: &[u8], files: &[&File]) {
    let descriptors: Vec<_> = files.iter().map(|file| file.as_fd()).collect();
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(4))];
    let mut ancillary = SendAncillaryBuffer::new(&mut space);
    if !descriptors.is_empty() {
        assert!(ancillary.push(SendAncillaryMessage::ScmRights(&descriptors)));
    }
    assert_eq!(
        sendmsg(
            stream,
            &[IoSlice::new(bytes)],
            &mut ancillary,
            SendFlags::NOSIGNAL
        )
        .unwrap(),
        bytes.len()
    );
    stream.shutdown(Shutdown::Write).unwrap();
}
#[test]
fn protocol_rejects_missing_extra_unsealed_and_mismatched_mode() {
    let root = rustix::process::getuid().is_root();
    let file = sealed_config(b"safe").unwrap();
    let header = Header {
        mode: WorkerMode::Check,
        engine: Engine::Xray,
        length: 4,
        binary_hash: [0; 32],
        config_hash: Hasher::digest(b"safe").into(),
    }
    .encode();
    for count in [0, 1, 2, 3] {
        let (sender, receiver) = UnixStream::pair().unwrap();
        send_request(&sender, &header, &vec![&file; count]);
        assert!(receive(&receiver, WorkerMode::Run).is_err());
    }
    let (sender, receiver) = UnixStream::pair().unwrap();
    send_request(&sender, &header, &[&file, &file]);
    let error = receive(&receiver, WorkerMode::Check).err().unwrap();
    assert_eq!(
        error,
        if root {
            WorkerError::Protocol
        } else {
            WorkerError::Peer
        }
    );
    let (sender, receiver) = UnixStream::pair().unwrap();
    send_request(&sender, &header[..24], &[&file, &file]);
    assert!(receive(&receiver, WorkerMode::Check).is_err());
}

/// Выполняется отдельно в собственном user namespace с настоящим закреплённым ELF.
#[test]
#[ignore = "Нужны canonical ELF, собранный yonik-worker и собственный user namespace"]
fn canonical_worker_process_check_and_run() {
    use std::{
        os::{fd::OwnedFd, unix::net::UnixListener},
        path::PathBuf,
    };
    assert!(rustix::process::getuid().is_root());
    use std::os::unix::fs::MetadataExt;
    let actual = std::fs::metadata("/proc/thread-self/ns/net").unwrap();
    let host = std::env::var("YONIK_NFT_TEST_HOST_NETNS").expect("YONIK_NFT_TEST_HOST_NETNS");
    let (device, inode) = host.split_once(':').unwrap();
    assert_ne!(
        (actual.dev(), actual.ino()),
        (
            device.parse::<u64>().unwrap(),
            inode.parse::<u64>().unwrap()
        ),
        "Нужен отдельный network namespace"
    );
    let worker = std::env::var_os("YONIK_WORKER_BIN").expect("YONIK_WORKER_BIN");
    let engine = match std::env::var("YONIK_SYSTEM_TUN_ENGINE").unwrap().as_str() {
        "xray" => Engine::Xray,
        "sing-box" => Engine::SingBox,
        _ => panic!("Неизвестное тестовое ядро"),
    };
    let path = PathBuf::from(std::env::var_os("YONIK_SYSTEM_TUN_BINARY").unwrap());
    {
        let bytes = std::fs::read(&path).unwrap();
        let binary =
            BinarySnapshot::load(&path, Sha256(Hasher::digest(&bytes).into()), engine).unwrap();
        let server = yonik_import::import_bytes(b"socks5://127.0.0.1:10999".to_vec())
            .unwrap()
            .servers
            .remove(0);
        let config =
            yonik_engine::compile(&server, engine, std::num::NonZeroU16::new(10808).unwrap())
                .unwrap();
        let payload = WorkerPayload::new(binary, config).unwrap();
        for mode in [WorkerMode::Check, WorkerMode::Run] {
            let directory = std::env::temp_dir().join(format!(
                "yonik-worker-test-{}-{:?}-{:?}",
                std::process::id(),
                engine,
                mode
            ));
            std::fs::create_dir(&directory).unwrap();
            let socket = directory.join("worker.sock");
            let listener = UnixListener::bind(&socket).unwrap();
            let fd: OwnedFd = listener.into();
            let mut child = Command::new(&worker)
                .arg(if mode == WorkerMode::Check {
                    "--check"
                } else {
                    "--run"
                })
                .stdin(Stdio::from(fd))
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            let stream = UnixStream::connect(&socket).unwrap();
            let ack = payload.send(&stream, mode).unwrap();
            assert_eq!(ack.pid, child.id());
            assert_eq!(
                ack.status,
                if mode == WorkerMode::Check {
                    WorkerStatus::Checked
                } else {
                    WorkerStatus::Accepted
                }
            );
            if mode == WorkerMode::Run {
                std::thread::sleep(Duration::from_millis(250));
                assert!(child.try_wait().unwrap().is_none());
                let executable = std::fs::read_link(format!("/proc/{}/exe", child.id())).unwrap();
                assert!(executable.to_string_lossy().contains("memfd:yonik-engine"));
                for descriptor in std::fs::read_dir(format!("/proc/{}/fd", child.id())).unwrap() {
                    let descriptor = descriptor.unwrap();
                    if descriptor.file_name() == "0" {
                        continue;
                    }
                    if let Ok(target) = std::fs::read_link(descriptor.path()) {
                        let target = target.to_string_lossy();
                        assert!(!target.contains("memfd:yonik-config"));
                        assert!(!target.contains("memfd:yonik-engine"));
                    }
                }
                child.kill().unwrap();
            }
            let status = child.wait().unwrap();
            if mode == WorkerMode::Check {
                assert!(status.success());
            }
            std::fs::remove_file(socket).unwrap();
            std::fs::remove_dir(directory).unwrap();
        }
    }
}

#[test]
fn received_descriptors_are_cloexec_and_executable_is_copied() {
    use rustix::io::{FdFlags, fcntl_getfd};
    use std::os::unix::fs::MetadataExt;
    let bytes = std::fs::read("/usr/bin/true").unwrap();
    let expected = Hasher::digest(&bytes).into();
    let binary = BinarySnapshot::load(
        std::path::Path::new("/usr/bin/true"),
        Sha256(expected),
        Engine::Xray,
    )
    .unwrap();
    let config = sealed_config(b"safe").unwrap();
    let mut header = Header {
        mode: WorkerMode::Check,
        engine: Engine::Xray,
        length: 4,
        binary_hash: expected,
        config_hash: Hasher::digest(b"safe").into(),
    };
    let (sender, receiver) = UnixStream::pair().unwrap();
    send_request(&sender, &header.encode(), &[binary.file(), &config]);
    if !rustix::process::getuid().is_root() {
        assert_eq!(
            receive(&receiver, WorkerMode::Check).err(),
            Some(WorkerError::Peer)
        );
        return;
    }
    let (copy, input) = receive(&receiver, WorkerMode::Check).unwrap();
    assert_ne!(
        copy.file().metadata().unwrap().ino(),
        binary.file().metadata().unwrap().ino()
    );
    assert!(fcntl_getfd(copy.file()).unwrap().contains(FdFlags::CLOEXEC));
    assert!(fcntl_getfd(&input).unwrap().contains(FdFlags::CLOEXEC));
    assert!(input.set_len(5).is_err());

    header.binary_hash[0] ^= 1;
    let (sender, receiver) = UnixStream::pair().unwrap();
    send_request(&sender, &header.encode(), &[binary.file(), &config]);
    assert_eq!(
        receive(&receiver, WorkerMode::Check).err(),
        Some(WorkerError::Protocol)
    );
}

#[test]
fn worker_owned_config_preserves_bytes_cursor_seals_and_budget() {
    use std::os::unix::fs::MetadataExt;
    let bytes = b"{\"secret\":\"fixture-only\"}";
    let mut source = sealed_config(bytes).unwrap();
    source.seek(SeekFrom::Start(7)).unwrap();
    let budget = crate::helper::memory::ByteBudget::new(bytes.len());
    let mut copy = worker_owned_config(&source, &budget).unwrap();
    assert_eq!(source.stream_position().unwrap(), 7);
    assert_eq!(copy.file.stream_position().unwrap(), 0);
    assert_eq!(
        copy.file.metadata().unwrap().uid(),
        rustix::process::getuid().as_raw()
    );
    assert_eq!(copy.file.metadata().unwrap().mode() & 0o777, 0o600);
    let mut actual = Vec::new();
    copy.file.read_to_end(&mut actual).unwrap();
    assert_eq!(actual, bytes);
    assert!(fcntl_get_seals(&copy.file).unwrap().contains(SEALS));
    assert!(copy.file.set_len(0).is_err());
    assert_eq!(budget.used(), bytes.len());
    assert!(worker_owned_config(&source, &budget).is_err());
    assert_eq!(budget.used(), bytes.len());
    drop(copy);
    assert_eq!(budget.used(), 0);
    assert!(worker_owned_config(&config_file().unwrap(), &budget).is_err());
    assert_eq!(budget.used(), 0);
}

#[test]
fn source_config_memfd_is_private_before_write_and_after_seal() {
    use std::os::unix::fs::MetadataExt;
    let mut file = config_file().unwrap();
    assert_eq!(file.metadata().unwrap().mode() & 0o777, 0o600);
    assert_eq!(
        file.metadata().unwrap().uid(),
        rustix::process::geteuid().as_raw()
    );
    assert_eq!(file.stream_position().unwrap(), 0);
    assert!(
        rustix::io::fcntl_getfd(&file)
            .unwrap()
            .contains(rustix::io::FdFlags::CLOEXEC)
    );
    let bytes = b"{\"fixture\":true}";
    file.write_all(bytes).unwrap();
    fcntl_add_seals(&file, SEALS).unwrap();
    file.seek(SeekFrom::Start(0)).unwrap();
    validate_file(&file, bytes.len(), Hasher::digest(bytes).into()).unwrap();
    assert_eq!(file.stream_position().unwrap(), 0);
    assert_eq!(file.metadata().unwrap().mode() & 0o777, 0o600);
    assert!(fcntl_get_seals(&file).unwrap().contains(SEALS));
    assert!(file.write_all(b"changed").is_err());
    let mut actual = [0u8; 16];
    assert_eq!(
        file.read_at(&mut actual[..bytes.len()], 0).unwrap(),
        bytes.len()
    );
    assert_eq!(&actual[..bytes.len()], bytes);
}

#[test]
fn bundle_v2_header_has_closed_ordered_roles_and_engine() {
    let header = Header {
        mode: WorkerMode::Check,
        engine: Engine::Xray,
        length: 12,
        binary_hash: [1; 32],
        config_hash: [2; 32],
    };
    let resource = yonik_engine::resource_bundle::ExternalRef {
        engine: Engine::Xray,
        digest: [3; 32],
        bytes: 25,
        records: 1,
        kind: yonik_engine::resource_bundle::ResourceKind::Cidrs,
        format_version: 1,
    };
    let mut encoded = header.encode().to_vec();
    encoded[7] = 2;
    encoded[10] = 1;
    encoded.extend_from_slice(&1u64.to_be_bytes());
    encoded.extend_from_slice(&2u64.to_be_bytes());
    encode_resource(&mut encoded, &resource);
    assert_eq!(decode_bundle_header(&encoded).unwrap().1.len(), 1);
    for length in [0, 79, 80, 81, 95, 96, 149] {
        assert!(decode_bundle_header(&encoded[..length.min(encoded.len())]).is_err());
    }
    for (position, value) in [
        (7, 3),
        (10, 0),
        (10, 17),
        (11, 1),
        (96, 2),
        (97, 99),
        (101, 9),
    ] {
        let mut wrong = encoded.clone();
        wrong[position] = value;
        assert!(decode_bundle_header(&wrong).is_err());
    }
    encoded[10] = 2;
    encode_resource(&mut encoded, &resource);
    assert!(decode_bundle_header(&encoded).is_err());
}
