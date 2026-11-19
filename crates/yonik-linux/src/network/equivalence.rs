//! Эквивалентность сетевого контракта без packet counters и служебных timestamps.
//! Не обновляет поколения и не заменяет guards потери Netlink/DNS/manager events.
use super::topology::TopologyCapture;
use super::{KernelRoute, LinuxAddress, LinuxLink, LinuxRoute, LinuxTopology, NetworkAttribute};
use std::{collections::BTreeSet, net::Ipv4Addr, time::Duration};
use tokio::time::Instant;

#[derive(Clone, Copy)]
pub(crate) struct CaptureWindow {
    pub(crate) start: Instant,
    pub(crate) end: Instant,
}

#[derive(Clone, Copy)]
pub(crate) struct RouteCapture {
    pub(crate) window: CaptureWindow,
    pub(crate) clock_ticks: Option<u64>,
}
impl RouteCapture {
    pub(crate) fn new(start: Instant, end: Instant) -> Self {
        Self {
            window: CaptureWindow { start, end },
            clock_ticks: clock_ticks(),
        }
    }
}
// AT_CLKTCK — тот же process parameter, который возвращает sysconf(_SC_CLK_TCK).
// Читаем собственный auxv один раз, без libc unsafe и новых dependency features.
fn clock_ticks() -> Option<u64> {
    static TICKS: std::sync::OnceLock<Option<u64>> = std::sync::OnceLock::new();
    *TICKS.get_or_init(|| {
        use std::io::Read;
        let mut bytes = Vec::new();
        std::fs::File::open("/proc/self/auxv")
            .ok()?
            .take(4097)
            .read_to_end(&mut bytes)
            .ok()?;
        if bytes.len() > 4096 {
            return None;
        }
        parse_clock_ticks(&bytes)
    })
}
fn parse_clock_ticks(bytes: &[u8]) -> Option<u64> {
    let word = std::mem::size_of::<usize>();
    if bytes.len() % (2 * word) != 0 {
        return None;
    }
    let mut result = None;
    for pair in bytes.chunks_exact(2 * word) {
        let key = usize::from_ne_bytes(pair[..word].try_into().ok()?);
        let value = usize::from_ne_bytes(pair[word..].try_into().ok()?);
        if key == 0 {
            return result;
        }
        if key == 17 {
            if result.is_some() || value == 0 || value > 1_000_000_000 {
                return None;
            }
            result = Some(value as u64);
        }
    }
    None
}

#[derive(Clone, Copy)]
enum Context {
    Link,
    Address(Option<(CaptureWindow, CaptureWindow)>),
    RenewedDhcp(CaptureWindow, [Instant; 2]),
    Route(Option<(RouteCapture, RouteCapture)>),
    Families,
    Inet6,
}

macro_rules! equal_record {
    ($ty:ident, $left:ident, $right:ident, $attrs:ident, $context:expr; $($field:ident),+ $(,)?) => {{
        // Новый типизированный selector должен ломать сборку до явного включения.
        let $ty { $($field: _),+, $attrs: _ } = $left;
        true $(&& $left.$field == $right.$field)+
            && attributes_equal(&$left.$attrs, &$right.$attrs, $context)
    }};
}
pub(crate) fn same_external_topology(left: &LinuxTopology, right: &LinuxTopology) -> bool {
    same_topology(left, right, None, &[])
}
pub(crate) fn same_captured_topology(
    left: &LinuxTopology,
    left_time: TopologyCapture,
    right: &LinuxTopology,
    right_time: TopologyCapture,
) -> bool {
    same_topology(left, right, Some((left_time, right_time)), &[])
}
#[derive(Clone, Copy)]
pub(crate) struct RenewedDhcpAddress {
    pub(crate) index: u32,
    pub(crate) local: Ipv4Addr,
    pub(crate) prefix: u8,
    pub(crate) expiries: [Instant; 2],
}

pub(crate) fn same_session_topology(
    left: (&LinuxTopology, TopologyCapture),
    right: (&LinuxTopology, TopologyCapture),
    dhcp: &[RenewedDhcpAddress],
) -> bool {
    same_topology(left.0, right.0, Some((left.1, right.1)), dhcp)
}
#[cfg(test)]
pub(crate) fn diagnostic_class_matches(
    left: &LinuxTopology,
    lt: TopologyCapture,
    right: &LinuxTopology,
    rt: TopologyCapture,
) -> [(&'static str, bool); 6] {
    [
        ("namespace", left.namespace == right.namespace),
        (
            "link",
            left.links.len() == right.links.len()
                && left
                    .links
                    .iter()
                    .zip(&right.links)
                    .all(|(a, b)| same_link(a, b)),
        ),
        (
            "address",
            left.addresses.len() == right.addresses.len()
                && left.addresses.iter().zip(&right.addresses).all(|(a, b)| {
                    same_address(a, b, Some((lt.family(a.family), rt.family(b.family))))
                }),
        ),
        (
            "route",
            left.routes.len() == right.routes.len()
                && left
                    .routes
                    .iter()
                    .zip(&right.routes)
                    .all(|(a, b)| same_route(a, b, Some((lt.route(a.family), rt.route(b.family))))),
        ),
        ("rule", left.rules == right.rules),
        ("nexthop", left.nexthops == right.nexthops),
    ]
}
fn same_topology(
    left: &LinuxTopology,
    right: &LinuxTopology,
    times: Option<(TopologyCapture, TopologyCapture)>,
    dhcp: &[RenewedDhcpAddress],
) -> bool {
    let LinuxTopology {
        namespace: _,
        links: _,
        addresses: _,
        routes: _,
        rules: _,
        nexthops: _,
    } = left;
    left.namespace == right.namespace
        && left.rules == right.rules
        && left.nexthops == right.nexthops
        && left.links.len() == right.links.len()
        && left
            .links
            .iter()
            .zip(&right.links)
            .all(|(a, b)| same_link(a, b))
        && left.addresses.len() == right.addresses.len()
        && left.addresses.iter().zip(&right.addresses).all(|(a, b)| {
            let renewal = dhcp
                .binary_search_by_key(&a.index, |address| address.index)
                .ok();
            if let (Some(position), Some((_, capture))) = (renewal, times) {
                let address = &dhcp[position];
                if a.family == 2
                    && a.index == address.index
                    && a.prefix_len == address.prefix
                    && a.local.unwrap_or(a.address) == address.local
                {
                    return compare_address(
                        a,
                        b,
                        Context::RenewedDhcp(capture.family(2), address.expiries),
                    );
                }
            }
            same_address(
                a,
                b,
                times.map(|(a_time, b_time)| (a_time.family(a.family), b_time.family(b.family))),
            )
        })
        && left.routes.len() == right.routes.len()
        && left.routes.iter().zip(&right.routes).all(|(a, b)| {
            same_route(
                a,
                b,
                times.map(|(at, bt)| (at.route(a.family), bt.route(b.family))),
            )
        })
}
pub(super) fn same_link(left: &LinuxLink, right: &LinuxLink) -> bool {
    equal_record!(LinuxLink,left,right,unknown,Context::Link;index,link_type,flags,name,alias,mtu,master,parent,kind,operational_state)
}
fn same_address(
    left: &LinuxAddress,
    right: &LinuxAddress,
    times: Option<(CaptureWindow, CaptureWindow)>,
) -> bool {
    compare_address(left, right, Context::Address(times))
}
fn compare_address(left: &LinuxAddress, right: &LinuxAddress, context: Context) -> bool {
    equal_record!(LinuxAddress,left,right,unknown,context;family,index,address,local,prefix_len,scope,flags)
}
fn same_route(
    left: &LinuxRoute,
    right: &LinuxRoute,
    times: Option<(RouteCapture, RouteCapture)>,
) -> bool {
    equal_record!(LinuxRoute,left,right,unknown,Context::Route(times);family,destination,source,table,preferred_source,gateway,output_interface,input_interface,priority,protocol,kind,scope,tos,flags,multipath,nexthop_id)
}
#[cfg(test)]
fn same_kernel_route(left: &KernelRoute, right: &KernelRoute) -> bool {
    same_captured_kernel_route(left, right, None)
}
pub(crate) fn same_captured_kernel_route(
    left: &KernelRoute,
    right: &KernelRoute,
    times: Option<(RouteCapture, RouteCapture)>,
) -> bool {
    equal_record!(KernelRoute,left,right,attributes,Context::Route(times);namespace,query,table,output_interface,gateway,preferred_source,kind,flags,nexthop_id,incomplete)
}
fn attributes_equal(
    left: &[NetworkAttribute],
    right: &[NetworkAttribute],
    context: Context,
) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut seen = BTreeSet::new();
    left.iter().zip(right).all(|(a, b)| {
        a.kind == b.kind && seen.insert(a.kind) && value_equal(a.kind, &a.value, &b.value, context)
    })
}
fn value_equal(kind: u16, left: &[u8], right: &[u8], context: Context) -> bool {
    match (context, kind) {
        // rtnl_link_stats[64] содержат только счётчики. ABI длина должна совпасть.
        (Context::Link, 7) => left.len() == 96 && right.len() == 96,
        (Context::Link, 23) => {
            left.len() == right.len() && (192..=256).contains(&left.len()) && left.len() % 8 == 0
        }
        (Context::Link, 26 | 0x801a) => nested_equal(left, right, Context::Families),
        (Context::Families, 10 | 0x800a) => nested_equal(left, right, Context::Inet6),
        // Первый u64 сообщает число IPv6 counters; он сам не packet counter.
        (Context::Inet6, 3 | 6) => {
            left.len() == right.len()
                && (8..=2048).contains(&left.len())
                && left.len() % 8 == 0
                && left[..8] == right[..8]
        }
        // ifla_cacheinfo: max_reasm_len, timestamp, reachable_time, retrans_time.
        (Context::Inet6, 5) => {
            left.len() == 16
                && right.len() == 16
                && left[..4] == right[..4]
                && left[8..] == right[8..]
        }
        // ifa_cacheinfo: preferred/valid lifetimes остаются частью binding.
        (Context::Address(times), 6) => address_cache_equal(left, right, times),
        (Context::RenewedDhcp(window, expiries), 6) => {
            renewed_dhcp_cache(left, right, window, expiries)
        }
        // rta_cacheinfo: сохраняем expires и error, не сравниваем ref/use/clock.
        (Context::Route(times), 12) => {
            left.len() == 32
                && right.len() == 32
                && left[12..16] == right[12..16]
                && route_expiry_equal(
                    i64::from(i32::from_ne_bytes(
                        left[8..12].try_into().expect("Проверены 32 байта"),
                    )),
                    i64::from(i32::from_ne_bytes(
                        right[8..12].try_into().expect("Проверены 32 байта"),
                    )),
                    times,
                    false,
                    Instant::now(),
                )
                && left[20..24] == right[20..24]
        }
        (Context::Route(times), 23) => {
            left.len() == 4
                && right.len() == 4
                && route_expiry_equal(
                    i64::from(u32::from_ne_bytes(
                        left.try_into().expect("Проверены 4 байта"),
                    )),
                    i64::from(u32::from_ne_bytes(
                        right.try_into().expect("Проверены 4 байта"),
                    )),
                    times,
                    true,
                    Instant::now(),
                )
        }
        _ => left == right,
    }
}

fn renewed_dhcp_cache(
    left: &[u8],
    right: &[u8],
    window: CaptureWindow,
    expiries: [Instant; 2],
) -> bool {
    if left.len() != 16 || right.len() != 16 || left[8..12] != right[8..12] {
        return false;
    }
    let read_lifetimes = |bytes: &[u8]| {
        let preferred = u32::from_ne_bytes(bytes[..4].try_into().expect("Проверены 16 байт"));
        let valid = u32::from_ne_bytes(bytes[4..8].try_into().expect("Проверены 16 байт"));
        (preferred, valid)
    };
    let (old_preferred, old_valid) = read_lifetimes(left);
    let (preferred, valid) = read_lifetimes(right);
    // Демон и ядро переводят остаток срока в целые секунды. Учитываем
    // одну секунду по обе стороны измерения и проверяем оба срока.
    let matches_expiry = |seconds: u32, expected: Instant| {
        let low = window.start + Duration::from_secs(u64::from(seconds - 1));
        let high = window.end + Duration::from_secs(u64::from(seconds) + 1);
        Instant::now().max(window.end) < low && low <= expected && expected <= high
    };
    old_preferred > 0
        && old_preferred <= old_valid
        && old_valid < u32::MAX
        && preferred > 1
        && preferred <= valid
        && valid < u32::MAX
        && matches_expiry(preferred, expiries[0])
        && matches_expiry(valid, expiries[1])
}
fn route_expiry_equal(
    a: i64,
    b: i64,
    times: Option<(RouteCapture, RouteCapture)>,
    seconds: bool,
    now: Instant,
) -> bool {
    // CACHEINFO 0 означает отсутствие expiry. Отрицательное — уже expired;
    // INT_MAX может быть результатом saturation, не доказанный finite deadline.
    // EXPIRES — секунды; UINT_MAX соответствует INFINITY_LIFE_TIME.
    if seconds && (a == i64::from(u32::MAX) || b == i64::from(u32::MAX)) {
        return a == b;
    }
    if !seconds && (a == 0 || b == 0) {
        return a == b;
    }
    if a <= 0 || b <= 0 || (!seconds && (a >= i64::from(i32::MAX) || b >= i64::from(i32::MAX))) {
        return false;
    }
    let Some((before, after)) = times else {
        return false;
    };
    let (Some(hz), Some(other_hz)) = (before.clock_ticks, after.clock_ticks) else {
        return false;
    };
    if hz == 0 || hz != other_hz || hz > 1_000_000_000 {
        return false;
    }
    let (before, after) = (before.window, after.window);
    if before.start > before.end || after.start > after.end || before.end > after.start {
        return false;
    }
    let rate = if seconds { 1 } else { hz };
    // Floor при переводе jiffies в USER_HZ плюс дискретный момент jiffies.
    // На поддерживаемых Linux x86_64/aarch64 HZ >= USER_HZ. Для EXPIRES
    // к секундной дискретности добавляется один USER_HZ tick.
    let tick = Duration::from_nanos(1_000_000_000u64.div_ceil(hz));
    let quantum = Duration::from_nanos(1_000_000_000u64.div_ceil(rate));
    let duration = |value: i64| Duration::from_nanos((value as u64 * 1_000_000_000) / rate);
    let bounds = |value, window: CaptureWindow| {
        let nominal = duration(value);
        (
            window.start + nominal.saturating_sub(tick),
            window.end + nominal + quantum,
        )
    };
    let (low_a, high_a) = bounds(a, before);
    let (low_b, high_b) = bounds(b, after);
    let now = now.max(after.end);
    now < low_a && now < low_b && low_a < high_b && low_b < high_a
}
// Linux вычитает целое число секунд от tstamp. Поэтому expiry лежит
// в (read_start + remaining - 1s, read_end + remaining]. Сравниваем
// пересечение этих интервалов, без допуска, растущего при каждом sweep.
fn address_cache_equal(
    left: &[u8],
    right: &[u8],
    times: Option<(CaptureWindow, CaptureWindow)>,
) -> bool {
    address_cache_equal_at(left, right, times, Instant::now())
}
fn address_cache_equal_at(
    left: &[u8],
    right: &[u8],
    times: Option<(CaptureWindow, CaptureWindow)>,
    now: Instant,
) -> bool {
    if left.len() != 16 || right.len() != 16 || left[8..] != right[8..] {
        return false;
    }
    let Some((before, after)) = times else {
        return left == right;
    };
    if before.start > before.end || after.start > after.end || before.end > after.start {
        return false;
    }
    let now = now.max(after.end);
    [0, 4].into_iter().all(|offset| {
        let a = u32::from_ne_bytes(
            left[offset..offset + 4]
                .try_into()
                .expect("Проверены 16 байт"),
        );
        let b = u32::from_ne_bytes(
            right[offset..offset + 4]
                .try_into()
                .expect("Проверены 16 байт"),
        );
        if a == u32::MAX || b == u32::MAX {
            return a == b;
        }
        if a == 0 || b == 0 {
            return false;
        }
        let low_a = before.start + Duration::from_secs(u64::from(a - 1));
        let high_a = before.end + Duration::from_secs(u64::from(a));
        let low_b = after.start + Duration::from_secs(u64::from(b - 1));
        let high_b = after.end + Duration::from_secs(u64::from(b));
        // Не сохраняем сессию, если к концу чтения expiry уже возможно.
        now < low_a && now < low_b && low_a < high_b && low_b < high_a
    })
}
fn next_attribute<'a>(rest: &mut &'a [u8]) -> Result<Option<(u16, &'a [u8])>, ()> {
    if rest.is_empty() {
        return Ok(None);
    }
    if rest.len() < 4 {
        return Err(());
    }
    let length = usize::from(u16::from_ne_bytes([rest[0], rest[1]]));
    let aligned = (length + 3) & !3;
    if length < 4 || aligned > rest.len() {
        return Err(());
    }
    let kind = u16::from_ne_bytes([rest[2], rest[3]]);
    let value = &rest[4..length];
    *rest = &rest[aligned..];
    Ok(Some((kind, value)))
}
fn nested_equal(mut left: &[u8], mut right: &[u8], context: Context) -> bool {
    let mut seen = BTreeSet::new();
    loop {
        match (next_attribute(&mut left), next_attribute(&mut right)) {
            (Ok(None), Ok(None)) => return true,
            (Ok(Some((kind, a))), Ok(Some((other, b))))
                if kind == other && seen.len() < 128 && seen.insert(kind) =>
            {
                if !value_equal(kind, a, b, context) {
                    return false;
                }
            }
            _ => return false,
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{NetworkNamespace, RouteKind, RouteQuery};
    use std::num::NonZeroU32;
    fn route_cache(expires: i32) -> Vec<u8> {
        let mut bytes = vec![0; 32];
        bytes[8..12].copy_from_slice(&expires.to_ne_bytes());
        bytes
    }
    #[test]
    fn renewed_dhcp_cache_preserves_creation_time_and_finite_liveness() {
        let bytes = |words: [u32; 4]| {
            words
                .into_iter()
                .flat_map(u32::to_ne_bytes)
                .collect::<Vec<_>>()
        };
        let old = bytes([80, 100, 10, 20]);
        let now = Instant::now();
        let window = CaptureWindow {
            start: now,
            end: now,
        };
        let expiry = [now + Duration::from_secs(120); 2];
        assert!(renewed_dhcp_cache(
            &old,
            &bytes([120, 120, 10, 40]),
            window,
            expiry
        ));
        for invalid in [
            [120, 120, 11, 40],
            [0, 120, 10, 40],
            [1, 120, 10, 40],
            [121, 120, 10, 40],
            [180, 180, 10, 40],
            [120, u32::MAX, 10, 40],
        ] {
            assert!(!renewed_dhcp_cache(&old, &bytes(invalid), window, expiry));
        }
    }
    #[test]
    fn finite_ra_route_natural_countdown_remains_equivalent() {
        let t = Instant::now();
        assert!(value_equal(
            12,
            &route_cache(8640000),
            &route_cache(8639700),
            Context::Route(Some((route_window(t, 0), route_window(t, 3000))))
        ));
    }
    #[test]
    fn route_expiry_keeps_zero_signed_saturation_renewal_and_deadline_fences() {
        let t = Instant::now();
        let same = |a, b, elapsed, now, seconds| {
            route_expiry_equal(
                a,
                b,
                Some((route_window(t, 0), route_window(t, elapsed))),
                seconds,
                t + Duration::from_millis(now),
            )
        };
        assert!(same(10000, 9700, 3000, 3000, false));
        assert!(!same(10000, 10000, 3000, 3000, false)); // renewal
        assert!(!same(10000, 9600, 3000, 3000, false)); // сокращение срока
        assert!(!same(100, 0, 1000, 1000, false));
        assert!(!same(0, 100, 1000, 1000, false));
        assert!(same(0, 0, 1000, 1000, false)); // отсутствие expiry
        assert!(!same(-1, -1, 0, 0, false));
        assert!(!same(i64::from(i32::MAX), i64::from(i32::MAX), 0, 0, false));
        assert!(!same(100, 100, 0, 1000, false)); // истечение после dump
        assert!(same(100, 97, 3000, 3000, true)); // EXPIRES: секунды, не ticks
        assert!(!same(100, 100, 3000, 3000, true));
        assert!(!same(1, 0, 1000, 1000, true));
        assert!(!same(0, 0, 0, 0, true)); // явный EXPIRES=0 уже истёк
        assert!(same(
            i64::from(u32::MAX),
            i64::from(u32::MAX),
            1000,
            1000,
            true
        ));
        assert!(!same(i64::from(u32::MAX), 97, 3000, 3000, true));
        assert!(!same(100, i64::from(u32::MAX), 3000, 3000, true));
        let mut other = route_window(t, 3000);
        other.clock_ticks = Some(250);
        assert!(!route_expiry_equal(
            10000,
            9700,
            Some((route_window(t, 0), other)),
            false,
            t
        ));
        other.clock_ticks = None;
        assert!(!route_expiry_equal(
            10000,
            9700,
            Some((route_window(t, 0), other)),
            false,
            t
        ));
        // Время читающего процесса может быть не кратно USER_HZ tick.
        assert!(same(10000, 9999, 2, 2, false));
    }
    #[test]
    fn captured_escape_route_does_not_hide_error_id_metric_or_interface_changes() {
        let t = Instant::now();
        let mut before = route();
        before.attributes[0].value = route_cache(10000);
        let mut after = before.clone();
        after.attributes[0].value = route_cache(9700);
        let times = Some((route_window(t, 0), route_window(t, 3000)));
        assert!(same_captured_kernel_route(&before, &after, times));
        assert!(!same_captured_kernel_route(&before, &after, None));
        for change in 0..5 {
            let mut changed = after.clone();
            match change {
                0 => changed.attributes[0].value[12] = 1,
                1 => changed.attributes[0].value[20] = 1,
                2 => changed.output_interface = NonZeroU32::new(99),
                3 => changed.nexthop_id = Some(9),
                _ => changed.attributes.push(NetworkAttribute {
                    kind: 8,
                    value: vec![1, 2, 3, 4],
                }),
            }
            assert!(!same_captured_kernel_route(&before, &changed, times));
        }
        before.attributes.push(NetworkAttribute {
            kind: 23,
            value: 100u32.to_ne_bytes().to_vec(),
        });
        after.attributes.push(NetworkAttribute {
            kind: 23,
            value: 97u32.to_ne_bytes().to_vec(),
        });
        assert!(same_captured_kernel_route(&before, &after, times));
    }
    #[test]
    fn auxv_clock_ticks_are_bounded_unique_and_native_endian() {
        let encode = |pairs: &[(usize, usize)]| {
            pairs
                .iter()
                .flat_map(|(a, b)| [a.to_ne_bytes(), b.to_ne_bytes()].concat())
                .collect::<Vec<_>>()
        };
        assert_eq!(parse_clock_ticks(&encode(&[(17, 100), (0, 0)])), Some(100));
        for pairs in [
            vec![(17, 0), (0, 0)],
            vec![(17, 100)],
            vec![(17, 100), (17, 100), (0, 0)],
            vec![(0, 0)],
        ] {
            assert_eq!(parse_clock_ticks(&encode(&pairs)), None);
        }
        assert_eq!(parse_clock_ticks(&[1, 2, 3]), None);
        assert!(clock_ticks().is_some());
    }
    fn route_window(t: Instant, ms: u64) -> RouteCapture {
        RouteCapture {
            window: window(t, ms),
            clock_ticks: Some(100),
        }
    }
    fn window(t: Instant, ms: u64) -> CaptureWindow {
        let t = t + Duration::from_millis(ms);
        CaptureWindow { start: t, end: t }
    }
    fn cache(preferred: u32, valid: u32) -> Vec<u8> {
        [preferred, valid, 7, 9]
            .into_iter()
            .flat_map(u32::to_ne_bytes)
            .collect()
    }
    #[test]
    fn finite_address_natural_countdown_remains_equivalent() {
        let t = Instant::now();
        assert!(address_cache_equal(
            &cache(100, 200),
            &cache(99, 199),
            Some((window(t, 0), window(t, 1000)))
        ));
    }
    #[test]
    fn finite_lifetimes_use_capture_intervals_and_keep_renewal_and_expiry_fences() {
        let t = Instant::now();
        let equal = |a: Vec<u8>, b: Vec<u8>, elapsed: u64, now: u64| {
            address_cache_equal_at(
                &a,
                &b,
                Some((window(t, 0), window(t, elapsed))),
                t + Duration::from_millis(now),
            )
        };
        // Пересечение секундной границы возможно даже за 2 ms.
        assert!(equal(cache(100, 200), cache(99, 199), 2, 2));
        assert!(equal(cache(100, 200), cache(100, 200), 2, 2));
        assert!(equal(cache(100, 200), cache(90, 190), 10_000, 10_000));
        assert!(!equal(cache(100, 200), cache(100, 200), 10_000, 10_000));
        assert!(!equal(cache(100, 200), cache(88, 190), 10_000, 10_000));
        assert!(!equal(cache(100, 200), cache(90, 188), 10_000, 10_000));
        let mut renewed = cache(90, 190);
        renewed[12] = 10;
        assert!(!equal(cache(100, 200), renewed, 10_000, 10_000));
        let mut replaced = cache(90, 190);
        replaced[8] = 10;
        assert!(!equal(cache(100, 200), replaced, 10_000, 10_000));
        // Нулевой остаток и возможный expiry во время последующих dump/check
        // запрещены, даже если RTM_DELADDR/DEPRECATED ещё не обработаны.
        assert!(!equal(cache(2, 200), cache(0, 198), 2_000, 2_000));
        assert!(!equal(cache(2, 200), cache(2, 200), 0, 2_000));
        assert!(!equal(cache(u32::MAX, 2), cache(u32::MAX, 0), 2_000, 2_000));
        assert!(!equal(cache(u32::MAX, 2), cache(u32::MAX, 2), 0, 2_000));
        assert!(equal(
            cache(u32::MAX, u32::MAX),
            cache(u32::MAX, u32::MAX),
            1_000_000,
            1_000_000
        ));
        for (a, b) in [
            (cache(100, 200), cache(u32::MAX, u32::MAX)),
            (cache(u32::MAX, u32::MAX), cache(99, 199)),
        ] {
            assert!(!equal(a, b, 1_000, 1_000));
        }
        assert!(!address_cache_equal_at(
            &cache(100, 200),
            &cache(100, 200),
            Some((window(t, 1000), window(t, 0))),
            t
        ));
    }
    #[test]
    fn address_countdown_does_not_hide_address_link_flags_or_prefix_changes() {
        let t = Instant::now();
        let address = LinuxAddress {
            family: 2,
            index: 2,
            address: "192.0.2.1".parse().unwrap(),
            local: None,
            prefix_len: 24,
            scope: 0,
            flags: 0,
            unknown: vec![NetworkAttribute {
                kind: 6,
                value: cache(100, 200),
            }],
        };
        let mut current = address.clone();
        current.unknown[0].value = cache(99, 199);
        let times = Some((window(t, 0), window(t, 1000)));
        assert!(same_address(&address, &current, times));
        for change in 0..4 {
            let mut changed = current.clone();
            match change {
                0 => changed.address = "192.0.2.2".parse().unwrap(),
                1 => changed.index += 1,
                2 => changed.flags ^= 0x20,
                _ => changed.prefix_len -= 1,
            }
            assert!(!same_address(&address, &changed, times));
        }
        assert!(!same_address(&address, &current, None));
    }
    fn link() -> LinuxLink {
        LinuxLink {
            index: 2,
            link_type: 1,
            flags: 0x1001,
            name: b"eth0".to_vec(),
            alias: None,
            mtu: Some(1500),
            master: None,
            parent: None,
            kind: None,
            operational_state: Some(6),
            unknown: vec![NetworkAttribute {
                kind: 23,
                value: vec![0; 200],
            }],
        }
    }
    fn nested(kind: u16, value: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&((value.len() + 4) as u16).to_ne_bytes());
        bytes.extend_from_slice(&kind.to_ne_bytes());
        bytes.extend_from_slice(value);
        bytes.resize((bytes.len() + 3) & !3, 0);
        bytes
    }
    #[test]
    fn packet_counters_change_without_refreshing_network_selectors() {
        let expected = link();
        let mut current = expected.clone();
        current.unknown[0].value.fill(2);
        assert!(same_link(&expected, &current));
        current.mtu = Some(1400);
        assert!(!same_link(&expected, &current));
        current.mtu = expected.mtu;
        current.flags ^= 0x10000;
        assert!(!same_link(&expected, &current));
        current.flags = expected.flags;
        current.unknown.push(NetworkAttribute {
            kind: 999,
            value: vec![1],
        });
        assert!(!same_link(&expected, &current));
        current = expected.clone();
        current.unknown[0].value.pop();
        assert!(!same_link(&expected, &current));
    }
    #[test]
    fn ipv6_counters_do_not_hide_devconf_token_or_timers() {
        let stats = [2u64.to_ne_bytes(), 3u64.to_ne_bytes()].concat();
        let conf = nested(2, &[1u8; 16]);
        let token = nested(7, &[2u8; 16]);
        let mut payload = conf.clone();
        payload.extend(nested(3, &stats));
        payload.extend(token.clone());
        let expected = NetworkAttribute {
            kind: 26,
            value: nested(10, &payload),
        };
        let mut changed = conf.clone();
        changed.extend(nested(
            3,
            &[2u64.to_ne_bytes(), 99u64.to_ne_bytes()].concat(),
        ));
        changed.extend(token.clone());
        assert!(attributes_equal(
            std::slice::from_ref(&expected),
            &[NetworkAttribute {
                kind: 26,
                value: nested(10, &changed)
            }],
            Context::Link
        ));
        for field in [2, 7] {
            let mut value = if field == 2 {
                nested(2, &[9u8; 16])
            } else {
                conf.clone()
            };
            value.extend(nested(3, &stats));
            value.extend(if field == 7 {
                nested(7, &[9u8; 16])
            } else {
                token.clone()
            });
            assert!(!attributes_equal(
                std::slice::from_ref(&expected),
                &[NetworkAttribute {
                    kind: 26,
                    value: nested(10, &value)
                }],
                Context::Link
            ));
        }
        let bad = NetworkAttribute {
            kind: 26,
            value: vec![1, 2, 3],
        };
        assert!(!attributes_equal(
            std::slice::from_ref(&bad),
            std::slice::from_ref(&bad),
            Context::Link
        ));
    }
    fn route() -> KernelRoute {
        KernelRoute {
            namespace: NetworkNamespace {
                device: 1,
                inode: 1,
            },
            query: RouteQuery::new("192.0.2.1".parse().unwrap(), 969).with_mark(99),
            table: Some(254),
            output_interface: NonZeroU32::new(2),
            gateway: None,
            preferred_source: None,
            kind: RouteKind::Unicast,
            flags: 0,
            nexthop_id: None,
            attributes: vec![NetworkAttribute {
                kind: 12,
                value: vec![0; 32],
            }],
            incomplete: vec![],
        }
    }
    #[test]
    fn route_cache_usage_changes_without_hiding_expiration_error_or_context() {
        let expected = route();
        let mut current = expected.clone();
        current.attributes[0].value[16] = 2;
        assert!(same_kernel_route(&expected, &current));
        current.attributes[0].value[8] = 1;
        assert!(!same_kernel_route(&expected, &current));
        current = expected.clone();
        current.attributes[0].value[12] = 1;
        assert!(!same_kernel_route(&expected, &current));
        current = expected.clone();
        current.attributes[0].value[20] = 1;
        assert!(!same_kernel_route(&expected, &current));
        current = expected.clone();
        current.query = RouteQuery::new("192.0.2.2".parse().unwrap(), 969).with_mark(99);
        assert!(!same_kernel_route(&expected, &current));
    }
    #[test]
    fn flagged_unknown_representations_remain_opaque() {
        for kind in [0x4017, 0x8017] {
            let mut expected = link();
            expected.unknown[0].kind = kind;
            let mut current = expected.clone();
            current.unknown[0].value.fill(9);
            assert!(!same_link(&expected, &current));
        }
        let left = nested(10, &nested(0x4003, &[1; 16]));
        let right = nested(10, &nested(0x4003, &[2; 16]));
        assert!(!value_equal(26, &left, &right, Context::Link));
        assert!(!value_equal(
            0x4006,
            &[1; 16],
            &[2; 16],
            Context::Address(None)
        ));
    }
}
