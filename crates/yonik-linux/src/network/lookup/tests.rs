use super::*;
use std::net::{Ipv4Addr, Ipv6Addr};

fn query() -> RouteQuery {
    RouteQuery::new(Ipv4Addr::new(192, 0, 2, 3).into(), 1001)
}

#[test]
fn request_carries_actual_selectors() {
    let query = query()
        .with_source(Ipv4Addr::new(192, 0, 2, 2).into())
        .expect("семейство")
        .with_mark(42)
        .with_tos(16)
        .with_interfaces(NonZeroU32::new(2), NonZeroU32::new(3))
        .with_transport(TransportProtocol::Tcp, Some(12345), Some(443));
    let bytes = request_payload(&query);
    assert_eq!(&bytes[..8], &[2, 32, 32, 16, 0, 0, 0, 0]);
    assert_eq!(
        u32::from_ne_bytes(bytes[8..12].try_into().expect("flags")),
        0x1000
    );
    let attrs = attributes(&bytes[12..]).expect("атрибуты");
    for (kind, value) in [
        (25, 1001u32.to_ne_bytes()),
        (16, 42u32.to_ne_bytes()),
        (3, 2u32.to_ne_bytes()),
        (4, 3u32.to_ne_bytes()),
    ] {
        assert!(attrs.contains(&(kind, value.as_slice())));
    }
    assert!(attrs.contains(&(27, &[6][..])));
    assert!(attrs.contains(&(28, &12345u16.to_be_bytes()[..])));
    assert!(attrs.contains(&(29, &443u16.to_be_bytes()[..])));
}

#[test]
fn ipv6_and_source_family_validation() {
    assert_eq!(
        query().with_source(Ipv6Addr::LOCALHOST.into()),
        Err(NetworkReadError::Malformed)
    );
    let query = RouteQuery::new(Ipv6Addr::LOCALHOST.into(), 0).with_transport(
        TransportProtocol::Udp,
        None,
        Some(53),
    );
    let bytes = request_payload(&query);
    assert_eq!(&bytes[..3], &[10, 128, 0]);
    let attrs = attributes(&bytes[12..]).expect("атрибуты");
    assert!(attrs.contains(&(1, &Ipv6Addr::LOCALHOST.octets()[..])));
    assert!(attrs.contains(&(27, &[17][..])));
    assert!(!attrs.iter().any(|(kind, _)| *kind == 28));
}

fn response(kind: u8) -> Vec<u8> {
    let mut bytes = vec![2, 32, 0, 0, 254, 0, 0, kind, 0, 0, 0, 0];
    add_attribute(&mut bytes, 4, &2u32.to_ne_bytes());
    bytes
}
fn parse(bytes: &[u8]) -> Result<KernelRoute, NetworkReadError> {
    parse_reply(
        bytes,
        query(),
        NetworkNamespace {
            device: 1,
            inode: 2,
        },
    )
}

#[test]
fn selected_path_preserves_table_gateway_source_and_nexthop() {
    let mut bytes = response(1);
    add_attribute(&mut bytes, 15, &1000u32.to_ne_bytes());
    add_attribute(&mut bytes, 5, &[192, 0, 2, 1]);
    add_attribute(&mut bytes, 7, &[192, 0, 2, 2]);
    add_attribute(&mut bytes, 30, &8u32.to_ne_bytes());
    let route = parse(&bytes).expect("путь ядра");
    assert_eq!(route.table, Some(1000));
    assert_eq!(route.output_interface.map(NonZeroU32::get), Some(2));
    assert_eq!(route.gateway, Some(Ipv4Addr::new(192, 0, 2, 1).into()));
    assert_eq!(
        route.preferred_source,
        Some(Ipv4Addr::new(192, 0, 2, 2).into())
    );
    assert_eq!(route.nexthop_id, Some(8));
    assert_eq!(route.kind, RouteKind::Unicast);
    assert!(route.incomplete.is_empty());
}

#[test]
fn ipv6_router_preference_is_known_and_preserved() {
    let query = RouteQuery::new(Ipv6Addr::LOCALHOST.into(), 0);
    let namespace = NetworkNamespace {
        device: 1,
        inode: 2,
    };
    let mut bytes = response(1);
    bytes[..3].copy_from_slice(&[10, 128, 0]);
    add_attribute(&mut bytes, 20, &[0]);
    let route = parse_reply(&bytes, query.clone(), namespace).expect("предпочтение IPv6");
    assert!(route.incomplete.is_empty());
    assert_eq!(route.attributes.len(), 1);
    assert_eq!(route.attributes[0].kind, 20);
    assert_eq!(route.attributes[0].value, [0]);

    for invalid in [&[2][..], &[0, 0][..]] {
        let mut malformed = response(1);
        malformed[..3].copy_from_slice(&[10, 128, 0]);
        add_attribute(&mut malformed, 20, invalid);
        assert_eq!(
            parse_reply(&malformed, query.clone(), namespace).err(),
            Some(NetworkReadError::Malformed)
        );
    }
}

#[test]
fn ambiguous_multipath_is_preserved_without_selecting_first() {
    let mut bytes = response(1);
    add_attribute(&mut bytes, 9, &[8, 0, 0, 0, 9, 0, 0, 0]);
    add_attribute(&mut bytes, 222, &[9, 8, 7]);
    let route = parse(&bytes).expect("неполный ответ");
    assert!(route.incomplete.contains(&LookupIncomplete::Multipath));
    assert!(
        route
            .incomplete
            .contains(&LookupIncomplete::UnknownAttributes)
    );
    assert_eq!(route.attributes.len(), 2);
    assert_eq!(route.attributes[0].value, [8, 0, 0, 0, 9, 0, 0, 0]);
}

#[test]
fn rejects_duplicate_malformed_and_wrong_family() {
    let mut bytes = response(1);
    add_attribute(&mut bytes, 4, &3u32.to_ne_bytes());
    assert_eq!(parse(&bytes).err(), Some(NetworkReadError::Malformed));
    let mut bytes = response(1);
    add_attribute(&mut bytes, 5, &[1, 2, 3]);
    assert_eq!(parse(&bytes).err(), Some(NetworkReadError::Malformed));
    let mut bytes = response(1);
    bytes[0] = 10;
    assert_eq!(parse(&bytes).err(), Some(NetworkReadError::Malformed));
    assert_eq!(parse(&[2, 32]).err(), Some(NetworkReadError::Malformed));
}

#[test]
fn route_kinds_are_not_reachability_claims_and_debug_is_redacted() {
    for (value, kind) in [
        (2, RouteKind::Local),
        (6, RouteKind::Blackhole),
        (7, RouteKind::Unreachable),
        (8, RouteKind::Prohibit),
    ] {
        assert_eq!(parse(&response(value)).expect("тип").kind, kind);
    }
    let debug = format!("{:?}", parse(&response(1)).expect("путь"));
    assert!(!debug.contains("192.0.2"));
    assert!(!format!("{:?}", query()).contains("1001"));
}

#[tokio::test]
async fn rejects_invalid_deadline_before_opening_socket() {
    let (_sender, mut cancel) = Cancellation::new();
    for timeout in [Duration::ZERO, Duration::from_secs(6)] {
        assert_eq!(
            lookup_route(query(), &mut cancel, timeout).await.err(),
            Some(NetworkReadError::Limit)
        );
    }
}

#[test]
fn rejects_malformed_multipath_record() {
    for value in [
        &[0, 0, 0, 0, 0, 0, 0, 0][..],
        &[16, 0, 0, 0, 2, 0, 0, 0][..],
        &[8, 0, 0][..],
    ] {
        let mut bytes = response(1);
        add_attribute(&mut bytes, 9, value);
        assert_eq!(parse(&bytes).err(), Some(NetworkReadError::Malformed));
    }
}

#[tokio::test]
async fn cancellation_is_checked_before_socket_open() {
    let (sender, mut cancel) = Cancellation::new();
    sender.send_replace(true);
    assert_eq!(
        lookup_route(query(), &mut cancel, Duration::from_secs(1))
            .await
            .err(),
        Some(NetworkReadError::Cancelled)
    );
}

#[test]
fn route_cache_info_is_preserved_as_known_metadata() {
    let cache = vec![0; 32];
    let mut bytes = response(1);
    add_attribute(&mut bytes, 12, &cache);
    let route = parse(&bytes).unwrap();
    assert!(route.incomplete.is_empty());
    assert_eq!(
        route.attributes,
        vec![NetworkAttribute {
            kind: 12,
            value: cache
        }]
    );
}
#[test]
fn route_cache_unknown_shapes_flags_errors_and_duplicates_fail_closed() {
    for (kind, length) in [(12, 31), (12, 33), (0x400c, 32), (0x800c, 32)] {
        let mut bytes = response(1);
        let cache = vec![0; length];
        add_attribute(&mut bytes, kind, &cache);
        let route = parse(&bytes).unwrap();
        assert!(
            route
                .incomplete
                .contains(&LookupIncomplete::UnknownAttributes)
        );
        assert_eq!(
            route.attributes,
            vec![NetworkAttribute { kind, value: cache }]
        );
    }
    let mut bytes = response(1);
    add_attribute(&mut bytes, 12, &[0; 32]);
    add_attribute(&mut bytes, 0x400c, &[0; 32]);
    assert_eq!(parse(&bytes).err(), Some(NetworkReadError::Malformed));
    let mut bytes = response(1);
    add_attribute(&mut bytes, 12, &[0; 32]);
    add_attribute(&mut bytes, 222, &[1]);
    assert!(
        parse(&bytes)
            .unwrap()
            .incomplete
            .contains(&LookupIncomplete::UnknownAttributes)
    );
}

#[test]
fn cached_route_error_is_not_a_usable_endpoint_path() {
    let mut cache = vec![0; 32];
    cache[12..16].copy_from_slice(&113u32.to_ne_bytes());
    let mut bytes = response(1);
    add_attribute(&mut bytes, 12, &cache);
    let route = parse(&bytes).unwrap();
    assert_eq!(route.incomplete, vec![LookupIncomplete::CachedError]);
    assert_eq!(
        route.attributes,
        vec![NetworkAttribute {
            kind: 12,
            value: cache
        }]
    );
}
