//go:build linux && yonikpureinterop

package nativehooks

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	xnet "github.com/xtls/xray-core/common/net"
	"io"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type franceTCPConn struct {
	flowFakeConn
	ctx                      context.Context
	eof                      <-chan struct{}
	iv                       int
	afterUDP                 *atomic.Bool
	writes, neighbor, closes atomic.Int32
}

func (c *franceTCPConn) Read(b []byte) (int, error) {
	if c.iv < 16 {
		n := min(len(b), 16-c.iv)
		clear(b[:n])
		c.iv += n
		return n, nil
	}
	select {
	case <-c.eof:
		return 0, io.EOF
	case <-c.ctx.Done():
		return 0, c.ctx.Err()
	}
}
func (c *franceTCPConn) Write(b []byte) (int, error) {
	c.writes.Add(1)
	if c.afterUDP.Load() {
		c.neighbor.Add(1)
	}
	return len(b), nil
}
func (c *franceTCPConn) Close() error { c.closes.Add(1); return nil }

// USER admission/HELLO/image/Consumed — explicit skipped preseed. Одна actual
// broker/constructor session, descriptor/ACK и все bootstrap ACK — другой SUT.
func RunPureFranceSession(t *testing.T, consume func(context.Context, []byte, xnet.Destination, func(context.Context, xnet.Destination) (net.Conn, error), <-chan struct{}, chan<- struct{}) error) {
	if os.Getenv("YONIK_PURE_INTEROP") == "" {
		t.Skip("bounded stdio only")
	}
	scan := bufio.NewScanner(os.Stdin)
	scan.Buffer(make([]byte, 4096), 140000)
	pipe := &interopPipe{t: t, scan: scan, tx: 1}
	var init struct {
		Launch, Snapshot, Config string
		UDP                      [][2]uint16 `json:"udp_path"`
		TCP                      [][2]uint16 `json:"tcp_path"`
		Subject                  uint16
		Watermark                uint64
		OwnerKind                byte   `json:"owner_kind"`
		OwnerID                  uint64 `json:"owner_id"`
		KnownNS                  uint64 `json:"known_ns"`
		Consumed                 struct {
			Protocol, Family byte
			LocalPort        uint16 `json:"local_port"`
			RemotePort       uint16 `json:"remote_port"`
			Local, Remote    string
			OriginalPort     uint16 `json:"original_port"`
			Original         string
		}
	}
	if e := json.Unmarshal(pipe.read()["init"], &init); e != nil {
		t.Fatal(e)
	}
	decode := func(s string) []byte {
		b, e := hex.DecodeString(s)
		if e != nil {
			t.Fatal(e)
		}
		return b
	}
	launch, config, snapshot := decode(init.Launch), decode(init.Config), decode(init.Snapshot)
	r, e := decodeProfileLaunch(launch)
	if e != nil {
		t.Fatal(e)
	}
	pipe.launch = r
	now := time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)
	admission, e := admitProfile(r, config, pipe, func(m *profileCapsule) error {
		asset := snapshotAsset(snapshot)
		row := m.rows[10][0]
		if !bytes.Equal(asset.source[:], row[:32]) || !bytes.Equal(asset.digest[:], row[32:64]) || asset.size != uint64(u32(row, 64)) {
			return errProfile
		}
		_, e := decodeProfileSnapshot(snapshot, asset)
		return e
	}, func() time.Time { return now })
	if e != nil {
		t.Fatal("full admission", e)
	}
	pipe.rx = 1
	if len(init.UDP) != 1 || len(init.TCP) != 1 || init.UDP[0] == init.TCP[0] || init.Watermark != 2 {
		t.Fatal("two exact checked paths/watermark")
	}
	caseName := os.Getenv("YONIK_INTEROP_CASE")
	network := strings.Contains(caseName, "france-network-")
	resolverProtocol := byte(17)
	if network && strings.Contains(caseName, "-tcp-") {
		resolverProtocol = 6
	}
	foreign := strings.HasSuffix(caseName, "foreign-member")
	badQuestion := strings.HasSuffix(caseName, "wrong-question")
	lateACK := strings.HasSuffix(caseName, "late-ack")
	missingTCP := strings.HasSuffix(caseName, "missing-tcp-scope")
	if strings.HasSuffix(caseName, "missing-udp-scope") {
		// Под5 нет legitimate DatagramSource: actual setup должен отвергнуть
		// отсутствие ACK без fallback. USER/Consumed seed/effects ещё не созданы.
		f := newFlowFixture(t, r.mode)
		f.now = now
		f.p.admission = admission
		f.c.manifest = admission.capsule
		f.c.clock = func() time.Time { return f.now }
		f.c.sessionDeadline = now.Add(time.Minute)
		f.p.snapshot, e = decodeProfileSnapshot(snapshot, snapshotAsset(snapshot))
		if e != nil {
			t.Fatal(e)
		}
		ops := profileDNSSetupOps{now: func() time.Time { return f.now }, alive: func() bool { return true }, reject: func(profileProofPacket) error { return nil }}
		ops.send = func(b []byte) error { pipe.emit(map[string]any{"packet": hex.EncodeToString(b)}); return nil }
		ops.receive = func(time.Time) (profileProofPacket, error) {
			v := pipe.read()
			if v["setup_denied"] != nil {
				return profileProofPacket{}, errProfile
			}
			return profileProofPacket{}, fmt.Errorf("unexpected setup response")
		}
		if e = f.p.setupDNSV2(launch, now.Add(time.Second), 1000, ops); e == nil || f.p.dnsCodec5 || f.c.operations != 0 {
			t.Fatal("missing scope negotiated", e)
		}
		pipe.emit(map[string]any{"go_done": true, "france": true, "setup_denied": true, "cleanup": true, "operations": 0, "attempts": 0, "preseed_users": 0})
		return
	}
	f, old := datagramHostsFixture(t, r.mode)
	udp := old.Value(profileGrantKey{}).(*profileGrant)
	ur := udp.receipt
	u := ur.udp
	a := u.producer.association
	// USER dispatcher пропущен; его leaf packet context всё равно должен иметь
	// lifetime openConsumed/runFlow, а не lifetime всей общей session.
	packetCtx, packetCancel := context.WithCancel(f.p.ctx)
	u.ctx, u.cancel = packetCtx, packetCancel
	ur.association.ctx = packetCtx
	f.now = now
	f.c.clock = func() time.Time { return f.now }
	f.c.sessionDeadline = now.Add(time.Minute)
	f.p.admission = admission
	f.c.manifest = admission.capsule
	ur.id, udp.id = 1, 1
	ur.revision, udp.revision = 1, 1
	ur.tuple = [40]byte{}
	ur.tuple[0], ur.tuple[1] = 17, 4
	be.PutUint16(ur.tuple[4:], init.Consumed.LocalPort)
	be.PutUint16(ur.tuple[6:], init.Consumed.RemotePort)
	copy(ur.tuple[8:24], decode(init.Consumed.Local))
	copy(ur.tuple[24:], decode(init.Consumed.Remote))
	ur.original = profileDestinationValue{family: 4, network: 17, port: init.Consumed.OriginalPort, address: net.IP(decode(init.Consumed.Original)).String()}
	u.original, u.tuple = ur.original, ur.tuple
	a.original = ur.original
	udp.effective = ur.original
	udp.subject, udp.scope, udp.branch = init.Subject, init.UDP[0][0], byte(init.UDP[0][1])
	udp.stream = u16(f.c.manifest.rows[8][udp.scope], 12)
	udp.chain = u16(f.c.manifest.rows[8][udp.scope], 16)
	udp.ownerKind, udp.ownerID = init.OwnerKind, init.OwnerID
	udp.ownerDeadline = now.Add(time.Duration(init.KnownNS))
	udp.deadline = now.Add(time.Second)
	u.deadline = udp.deadline
	a.deadline = udp.deadline
	// TCP USER preseed — отдельные immutable flow/grant/tuple и fixed slots.
	tcprctx, tcprcancel := context.WithCancel(f.p.ctx)
	tcpgctx, tcpgcancel := context.WithCancel(tcprctx)
	tcpOriginal := ur.original
	tcpOriginal.network = 6
	tr := &profileReceipt{control: f.c, ctx: tcprctx, cancel: tcprcancel, original: tcpOriginal, id: 2, revision: 1, slot: 1, index: 0, provenance: 2, grantCount: 1, tuple: fakeFlowTuple(6)}
	be.PutUint16(tr.tuple[4:], 32002)
	be.PutUint16(tr.tuple[6:], 1080)
	tcp := &profileGrant{class: 1, receipt: tr, ctx: tcpgctx, cancel: tcpgcancel, effective: tcpOriginal, id: 2, revision: 1, slot: 1, subject: init.Subject, scope: init.TCP[0][0], branch: byte(init.TCP[0][1]), ownerKind: init.OwnerKind, ownerID: init.OwnerID, deadline: now.Add(time.Second), ownerDeadline: now.Add(time.Duration(init.KnownNS))}
	tcp.stream = u16(f.c.manifest.rows[8][tcp.scope], 12)
	tcp.chain = u16(f.c.manifest.rows[8][tcp.scope], 16)
	if f.c.receipts[1] != nil || f.c.grants[1] != nil {
		t.Fatal("preseed collision")
	}
	f.c.receipts[1] = tr
	f.c.grants[1] = tcp
	extra := uint64((len(tr.original.address)+15)&^15) + profileGrantCredit(tcp)
	if f.c.buffered+extra+f.c.manifest.memoryCredit > uint64(f.c.manifest.caps[4]) {
		t.Fatal("preseed cap")
	}
	f.c.buffered += extra
	// USER downstream credit/Completed OPEN являются явным leaf preseed, не ACK
	// bootstrap. Retirement ниже требует real Close34 из Rust перед освобождением.
	if f.c.buffered+profileUDPDownstreamCredit+f.c.manifest.memoryCredit > uint64(f.c.manifest.caps[4]) {
		t.Fatal("preseed downstream cap")
	}
	f.c.buffered += profileUDPDownstreamCredit
	u.open = &profileOperation{completed: true}
	u.producer.flows[0] = u
	u.producer.count = 1
	a.flows = 1
	f.c.highestFlow, f.c.highestGrant = 2, 2
	f.c.nextDNSQuery = 8
	f.sequence = init.Watermark
	f.p.snapshot, e = decodeProfileSnapshot(snapshot, snapshotAsset(snapshot))
	if e != nil {
		t.Fatal(e)
	}
	if f.p.proofs != nil {
		f.p.proofs.launch = r
	}
	f.c.udpBudget.launch = r
	a.launch = r
	f.p.dnsV2 = false
	f.p.dns4Metadata = nil
	f.p.dnsCodec5 = false
	ops := profileDNSSetupOps{now: func() time.Time { return f.now }, alive: func() bool { return true }, reject: func(profileProofPacket) error { return nil }}
	ops.send = func(b []byte) error { pipe.emit(map[string]any{"packet": hex.EncodeToString(b)}); return nil }
	ops.receive = func(time.Time) (profileProofPacket, error) {
		uid := uint32(1000)
		if r.mode == 2 {
			uid = 0
		}
		return profileProofPacket{body: pipe.packet(), credentials: 1, pid: int32(r.hostPID), uid: uid}, nil
	}
	if e = f.p.setupDNSV2(launch, now.Add(time.Second), 1000, ops); e != nil || !f.p.dnsCodec5 {
		t.Fatal("one exact5 setup", e)
	}
	var replies []profilePacket
	var kinds []uint16
	udpPhase := false
	receiveReply := func(seq uint64) error {
		response := pipe.packet()
		pipe.rx++
		p, e := r.decodePacket(response, pipe.rx)
		if e != nil {
			return e
		}
		if (profileDNSV2Operation(p.kind) || p.kind == 58) && !profileDNSV5Envelope(r, response, true, 0, 0, seq) {
			return errProfile
		}
		replies = append(replies, p)
		return nil
	}
	f.c.write = func(kind uint16, object uint64, body []byte) (uint64, error) {
		f.sequence++
		seq := f.sequence
		kinds = append(kinds, kind)
		if foreign && udpPhase && kind == 42 {
			body = append([]byte(nil), body...)
			body[len(body)-1] ^= 1
		}
		var raw []byte
		if profileDNSV2Operation(kind) || kind == 57 {
			raw = make([]byte, 65536)
			n, e := profileDNSV5Encode(r, kind, seq, 0, body, raw)
			if e != nil {
				return 0, e
			}
			raw = raw[:n]
		} else {
			raw = r.packet(kind, seq, 0, body)
			be.PutUint64(raw[112:], object)
		}
		pipe.emit(map[string]any{"packet": hex.EncodeToString(raw)})
		return seq, receiveReply(seq)
	}
	var dnsLeaf *interopDNSLeaf
	if network {
		dnsLeaf = interopNetworkOwnedIO(t, f, pipe, resolverProtocol, "fr.example.invalid.", 2, func(index int) bool { return badQuestion && index == 1 }, receiveReply, func() { kinds = append(kinds, 52) })
	}
	var held *profilePacket
	delayed := false
	accept := func() {
		for len(replies) > 0 {
			p := replies[0]
			replies = replies[1:]
			if lateACK && udpPhase && !delayed && p.kind == 46 && len(p.body) > 3 && p.body[3] == 3 {
				copy := p
				held, delayed = &copy, true
				pipe.emit(map[string]any{"event": map[string]any{"name": "ack_hold", "target": 3, "id": u64(p.body, 8), "reply": p.reply}})
				continue
			}
			if e := f.c.accept(p); e != nil {
				t.Fatalf("accept %d/%d: %v", p.kind, p.reply, e)
			}
			if network && p.kind == 41 && len(p.body) > 2 && p.body[2] == 1 {
				// Только read-only диагностика после actual ACK; credits/owners
				// не освобождаются и следующая операция не синтезируется.
				f.c.mu.Lock()
				pipe.emit(map[string]any{"event": map[string]any{"name": "network_credit_state", "producer": u64(p.body, 8), "pending": f.c.profilePendingUsed(), "operations": f.c.operations, "waiter_pending": profileNetworkWaiterPending, "pending_cap": min(64, int(f.c.manifest.caps[3])), "buffered": f.c.buffered, "metadata": f.c.manifest.memoryCredit, "memory_cap": f.c.manifest.caps[4], "waiter_memory": profileHostsObservationCredit, "history": f.c.dnsHistoryUsed, "tasks": f.c.dnsTasksUsed}})
				f.c.mu.Unlock()
			}
		}
	}
	tick := func() {
		if e := f.c.tick(); e != nil {
			t.Fatal("tick", e)
		}
		accept()
	}
	contextFor := func(g *profileGrant) context.Context {
		return ProfileBootstrapRawContext(context.WithValue(context.WithValue(context.WithValue(f.p.ctx, profileContextKey{}, f.p), profileReceiptKey{}, g.receipt), profileGrantKey{}, g), true)
	}
	tcpctx, udpctx := contextFor(tcp), contextFor(udp)
	resume, eof := make(chan struct{}), make(chan struct{})
	ready := make(chan struct{}, 1)
	tcpDone := make(chan error, 1)
	udpDone := make(chan error, 1)
	var afterUDP atomic.Bool
	tc := &franceTCPConn{ctx: tcpctx, eof: eof, afterUDP: &afterUDP}
	tcpOpens, udpOpens, udpSends, udpCloses := 0, 0, 0, 0
	dial := func(ctx context.Context, d xnet.Destination) (net.Conn, error) {
		if ProfilePhysicalGate(ctx) != nil || d.Network != xnet.Network_TCP || d.Address.String() != "203.0.113.80" || d.Port != 443 {
			return nil, fmt.Errorf("TCP conjunction")
		}
		tcpOpens++
		ready <- struct{}{}
		return tc, nil
	}
	f.p.datagramIO = func(d *profileBootstrapDatagramPermission) (*profileDNSOwnedSocket, error) {
		if !f.c.datagramPermissionLive(d) || d.target.network != 17 || d.target.port != 443 || d.target.address != "203.0.113.80" {
			return nil, errProfile
		}
		udpOpens++
		life, cancel := context.WithCancel(d.context())
		return &profileDNSOwnedSocket{ctx: life, cancel: cancel, destination: d.target, gateIO: func() error {
			f.c.mu.Lock()
			defer f.c.mu.Unlock()
			if !f.c.datagramPermissionLive(d) {
				return errProfile
			}
			return nil
		}, writeIO: func(b []byte) (int, error) { udpSends++; return len(b), nil }, readIO: func([]byte) (int, error) { return 0, io.EOF }, closeFD: func() error { udpCloses++; return nil }}, nil
	}
	go func() {
		e := ProfilePrepareChain(tcpctx, nil)
		if missingTCP {
			if e == nil {
				tcpDone <- fmt.Errorf("TCP without Source5")
			} else {
				tcpDone <- nil
			}
			return
		}
		if e != nil {
			tcpDone <- e
			return
		}
		tcpDone <- consume(tcpctx, config, profileNumericDestination(tr.original), dial, resume, eof)
	}()
	deadline := time.After(3 * time.Second)
	until := func(done <-chan error, opening bool) {
		for {
			select {
			case op := <-f.p.flowQueue:
				if e := f.c.dispatch(op); e != nil {
					t.Fatal("dispatch", op.kind, e)
				}
				accept()
			case <-ready:
				if opening {
					return
				}
				t.Fatal("extra TCP open")
			case e := <-done:
				if e != nil {
					t.Fatal("SS Process", e)
				}
				if opening {
					t.Fatal("TCP ended before neighbor")
				}
				return
			case <-deadline:
				t.Fatal("France actor deadline")
			}
		}
	}
	until(tcpDone, !missingTCP)
	udpPhase = true
	cancelParent := strings.HasSuffix(caseName, "parent-cancel")
	second := strings.HasSuffix(caseName, "second-send")
	go func() {
		if e := ProfilePrepareChain(udpctx, nil); e != nil {
			if foreign || badQuestion {
				udpDone <- nil
				return
			}
			udpDone <- e
			return
		}
		if cancelParent {
			f.c.mu.Lock()
			f.c.closeGrant(udp)
			f.c.mu.Unlock()
		}
		e := consume(udpctx, config, profileNumericDestination(ur.original), dial, resume, eof)
		if (e != nil) != (cancelParent || second) {
			udpDone <- fmt.Errorf("UDP Process result: %v", e)
			return
		}
		udpDone <- nil
	}()
	until(udpDone, false)
	udpJoins := 0
	if !cancelParent && !foreign && !badQuestion {
		d := f.c.datagramForGrant(udp)
		if d == nil || d.conn == nil || !d.conn.managedStarted || !d.conn.closing || d.conn.readActive || d.conn.writeActive {
			t.Fatal("actual SS UDP managed tasks not joined")
		}
		udpJoins = 2
	}
	// Закрываем только UDP derivatives; исходный TCP и его SS tasks живы.
	closeNetworkIO := func(parent *profileGrant) {
		if !network {
			return
		}
		for _, n := range f.c.networkBootstraps[:f.c.networkBootstrapUsed] {
			if (parent == nil || n.parent == parent) && n.result != nil && n.result.networkConn != nil {
				if e := n.result.networkConn.Close(); e != nil {
					t.Fatal(e)
				}
			}
		}
	}
	closeNetworkIO(udp)
	f.c.mu.Lock()
	if network {
		for _, n := range f.c.networkBootstraps[:f.c.networkBootstrapUsed] {
			if n.parent == udp {
				f.c.networkBootstrapClose(n)
			}
		}
	}
	for _, h := range f.c.hostsObservations[:f.c.hostsObservationUsed] {
		if h.root == udp {
			f.c.hostsObservationClose(h)
		}
	}
	f.c.mu.Unlock()
	for i := 0; i < 64; i++ {
		tick()
		if held != nil {
			for j := 0; j < 3; j++ {
				tick()
			}
			for _, n := range f.c.networkBootstraps[:f.c.networkBootstrapUsed] {
				if n.parent == udp && (n.service.cancelSent || n.released || n.service.networkCleanupRefs != 1 || n.transport.released || f.c.dnsCleanupResult() == nil) {
					t.Fatal("held ACK lost UDP custody")
				}
			}
			if e := f.c.accept(*held); e != nil {
				t.Fatal("actual held ACK", e)
			}
			pipe.emit(map[string]any{"event": map[string]any{"name": "ack_release", "target": 3, "id": u64(held.body, 8), "reply": held.reply}})
			held = nil
		}
	}
	if !f.c.grantLive(tcp) || tc.closes.Load() != 0 {
		t.Fatal("UDP cleanup invalidated TCP")
	}
	for _, b := range f.c.datagramParents[:f.c.datagramParentUsed] {
		if !b.released || b.unknown {
			t.Fatal("UDP binding not ACK retired")
		}
	}
	if !missingTCP {
		pipe.emit(map[string]any{"event": map[string]any{"name": "tcp_neighbor_after_udp_cleanup", "grant": tcp.id, "protocol": 6}})
	}
	// Неверная branch authority не должна дойти до leaf factory.
	cross := 0
	if _, e := ProfileDialBootstrap(udpctx, xnet.TCPDestination(xnet.IPAddress([]byte{203, 0, 113, 80}), 443), func(context.Context, xnet.Destination) (net.Conn, error) { cross++; return tc, nil }); e == nil || cross != 0 {
		t.Fatal("UDP permission aliased TCP")
	}
	if c, handled, e := ProfileDialBootstrapDatagram(tcpctx, xnet.UDPDestination(xnet.IPAddress([]byte{203, 0, 113, 80}), 443)); c != nil || handled && e == nil {
		t.Fatal("TCP permission aliased UDP")
	}
	afterUDP.Store(true)
	close(resume)
	if !missingTCP {
		until(tcpDone, false)
	}
	if (!missingTCP && (tcpOpens != 1 || tc.closes.Load() != 1 || tc.neighbor.Load() == 0)) || (missingTCP && (tcpOpens != 0 || tc.closes.Load() != 0 || tc.neighbor.Load() != 0)) {
		t.Fatal("actual TCP SS neighbor", tcpOpens, tc.closes.Load(), tc.neighbor.Load())
	}
	expected := 1
	if cancelParent || foreign || badQuestion {
		expected = 0
	}
	if udpOpens != expected || udpSends != expected || udpCloses != expected {
		t.Fatal("one UDP packet", udpOpens, udpSends, udpCloses)
	}
	packetCancel()
	closeNetworkIO(nil)
	f.c.mu.Lock()
	if network {
		for _, n := range f.c.networkBootstraps[:f.c.networkBootstrapUsed] {
			f.c.networkBootstrapClose(n)
		}
	}
	for _, h := range f.c.hostsObservations[:f.c.hostsObservationUsed] {
		f.c.hostsObservationClose(h)
	}
	f.c.closeGrant(tcp)
	f.c.closeGrant(udp)
	f.c.closeReceipt(tr)
	f.c.closeReceipt(ur)
	f.c.mu.Unlock()
	for i := 0; i < 64; i++ {
		tick()
	}
	if !u.producer.flowRetired(u) {
		t.Fatal("USER source close lacks actual Rust ACK")
	}
	u.producer.retireFlow(0, u)
	if e := a.CloseAndJoin(); e != nil {
		t.Fatal("fake receiver close/join", e)
	}
	for _, g := range f.c.grants {
		if g != nil {
			t.Fatal("retained grant")
		}
	}
	for _, r := range f.c.receipts {
		if r != nil {
			t.Fatal("retained receipt")
		}
	}
	for _, h := range f.c.hostsObservations[:f.c.hostsObservationUsed] {
		if !h.released || h.unknown {
			t.Fatal("retained HOSTS")
		}
	}
	if f.c.operations != 0 || a.credit || a.flows != 0 || u.credit || a.receiver != nil {
		t.Fatal("owned custody not zero", f.c.operations, a.credit, a.flows, u.credit)
	}
	if network {
		if dnsLeaf.used != 2 || dnsLeaf.factories != 2 || dnsLeaf.writes != 2 || dnsLeaf.closes != 2 || dnsLeaf.entries[0].socket == dnsLeaf.entries[1].socket || dnsLeaf.entries[0].duplicate == dnsLeaf.entries[1].duplicate {
			t.Fatal("exchange-owned DNS leaves", dnsLeaf)
		}
		for _, entry := range dnsLeaf.entries {
			if !entry.sent || !entry.duplicate.closed {
				t.Fatal("DNS duplicate retained")
			}
		}
		for _, n := range f.c.networkBootstraps[:f.c.networkBootstrapUsed] {
			if !n.released || n.unknown || !n.context.released || n.transport.started != n.op.sent || n.peer.network != resolverProtocol {
				t.Fatal("NETWORK custody/anchor")
			}
		}
		if lateACK && !delayed {
			t.Fatal("missing actual held ACK")
		}
	}
	pipe.emit(map[string]any{"go_done": true, "france": true, "network": network, "resolver_protocol": resolverProtocol, "late_ack": delayed, "mode": r.mode, "tcp_opens": tcpOpens, "tcp_neighbor_writes": tc.neighbor.Load(), "tcp_closes": tc.closes.Load(), "udp_opens": udpOpens, "udp_sends": udpSends, "udp_closes": udpCloses, "udp_tasks_joined": udpJoins, "operations": f.c.operations, "cleanup": true, "kinds": kinds, "preseed_user_skipped": true, "watermark": init.Watermark, "parent_cancel": cancelParent, "second_send": second, "missing_tcp": missingTCP})
}
