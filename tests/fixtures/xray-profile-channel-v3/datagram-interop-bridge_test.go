//go:build linux

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
	"testing"
	"time"
)

// Только новый test member: production actor/encoder/consumer не заменяются.
func TestPureStatefulDatagramHostsStdioBridge(t *testing.T) {
	runPureDatagramHosts(t, nil)
}

// External test package вызывает actual SS Client.Process без import cycle.
func RunPureDatagramHosts(t *testing.T, consume func(context.Context, xnet.Destination, xnet.Destination) error) {
	runPureDatagramHosts(t, consume)
}
func runPureDatagramHosts(t *testing.T, consume func(context.Context, xnet.Destination, xnet.Destination) error) {
	if os.Getenv("YONIK_PURE_INTEROP") == "" {
		t.Skip("только bounded relay")
	}
	scan := bufio.NewScanner(os.Stdin)
	scan.Buffer(make([]byte, 4096), 140000)
	pipe := &interopPipe{t: t, scan: scan, tx: 1}
	var init struct {
		Launch, Snapshot, Config string
		Path                     [][2]uint16
		Subject                  uint16
		User                     struct {
			Grant, Flow, Revision uint64
			OwnerKind             byte   `json:"owner_kind"`
			OwnerID               uint64 `json:"owner_id"`
			KnownNS               uint64 `json:"known_ns"`
		}
		Consumed struct {
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
	launch := decode(init.Launch)
	r, e := decodeProfileLaunch(launch)
	if e != nil {
		t.Fatal(e)
	}
	pipe.launch = r
	snapshot := decode(init.Snapshot)
	now := time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)
	admission, e := admitProfile(r, decode(init.Config), pipe, func(m *profileCapsule) error {
		asset := snapshotAsset(snapshot)
		row := m.rows[10][0]
		if !bytes.Equal(asset.source[:], row[:32]) || !bytes.Equal(asset.digest[:], row[32:64]) || asset.size != uint64(u32(row, 64)) {
			return errProfile
		}
		_, e := decodeProfileSnapshot(snapshot, asset)
		return e
	}, func() time.Time { return now })
	if e != nil {
		t.Fatal("admission", e)
	}
	pipe.rx = 1
	caseName := os.Getenv("YONIK_INTEROP_CASE")
	network := strings.Contains(caseName, "udp-network-")
	badQuestion := strings.HasSuffix(caseName, "wrong-question")
	lateAck := strings.HasSuffix(caseName, "late-ack")
	protocol := byte(17)
	if network && strings.Contains(caseName, "-tcp-") {
		protocol = 6
	}
	// USER admission/Consumed являются явным общим preseed. Ни одного bootstrap ACK.
	f, oldctx := datagramHostsFixture(t, r.mode)
	parent := oldctx.Value(profileGrantKey{}).(*profileGrant)
	receipt := parent.receipt
	u := receipt.udp
	a := u.producer.association
	f.now = now
	f.c.clock = func() time.Time { return f.now }
	f.c.sessionDeadline = now.Add(time.Minute)
	f.p.admission = admission
	f.c.manifest = admission.capsule
	parent.id = init.User.Grant
	receipt.id = init.User.Flow
	parent.revision = init.User.Revision
	receipt.revision = init.User.Revision
	parent.ownerKind = init.User.OwnerKind
	parent.ownerID = init.User.OwnerID
	parent.ownerDeadline = now.Add(time.Duration(init.User.KnownNS))
	parent.deadline = now.Add(time.Second)
	u.deadline = now.Add(time.Second)
	a.deadline = now.Add(time.Second)
	receipt.tuple = [40]byte{}
	receipt.tuple[0], receipt.tuple[1] = init.Consumed.Protocol, init.Consumed.Family
	be.PutUint16(receipt.tuple[4:], init.Consumed.LocalPort)
	be.PutUint16(receipt.tuple[6:], init.Consumed.RemotePort)
	copy(receipt.tuple[8:24], decode(init.Consumed.Local))
	copy(receipt.tuple[24:], decode(init.Consumed.Remote))
	u.tuple = receipt.tuple
	receipt.original = profileDestinationValue{family: 4, network: 17, port: init.Consumed.OriginalPort, address: net.IP(decode(init.Consumed.Original)).String()}
	u.original = receipt.original
	a.original = receipt.original
	parent.subject = init.Subject
	parent.scope = init.Path[0][0]
	parent.branch = byte(init.Path[0][1])
	parent.effective = receipt.original
	parent.stream = u16(f.c.manifest.rows[8][parent.scope], 12)
	parent.chain = u16(f.c.manifest.rows[8][parent.scope], 16)
	f.c.highestFlow = receipt.id
	f.c.highestGrant = parent.id
	f.c.nextDNSQuery = 8
	preseedOperations := f.c.operations
	if r.mode == 1 && (parent.ownerKind != 0 || parent.ownerID != 0) || r.mode == 2 && init.User.KnownNS != uint64(20*time.Millisecond) {
		t.Fatal("common USER owner preseed")
	}
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
	if e = f.p.setupDNSV2(launch, f.now.Add(time.Second), 1000, ops); e != nil || !f.p.dnsCodec5 {
		t.Fatal("exact5 setup", e)
	}
	foreign := strings.HasSuffix(caseName, "foreign-member")
	cancelParent := strings.HasSuffix(caseName, "parent-cancel")
	replay := strings.HasSuffix(caseName, "replay")
	f.sequence = 2
	var replies []profilePacket
	var held *profilePacket
	delayed := false
	kinds := []uint16{}
	receiveReply := func(seq uint64) error {
		response := pipe.packet()
		pipe.rx++
		packet, e := r.decodePacket(response, pipe.rx)
		if e != nil {
			return e
		}
		if (profileDNSV2Operation(packet.kind) || packet.kind == 58) && !profileDNSV5Envelope(r, response, true, 0, 0, seq) {
			return errProfile
		}
		replies = append(replies, packet)
		return nil
	}
	f.c.write = func(kind uint16, object uint64, body []byte) (uint64, error) {
		f.sequence++
		seq := f.sequence
		kinds = append(kinds, kind)
		if foreign && kind == 42 {
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
		dnsLeaf = interopNetworkProtocolIO(t, f, pipe, badQuestion, protocol, receiveReply, func() { kinds = append(kinds, 52) })
	}
	accept := func() {
		for len(replies) > 0 {
			p := replies[0]
			replies = replies[1:]
			if lateAck && !delayed && p.kind == 46 && len(p.body) > 3 && p.body[3] == 3 {
				copy := p
				held = &copy
				delayed = true
				pipe.emit(map[string]any{"event": map[string]any{"name": "ack_hold", "target": 3, "id": u64(p.body, 8), "reply": p.reply}})
				continue
			}
			if e := f.c.accept(p); e != nil {
				t.Fatalf("accept %d/%d: %v", p.kind, p.reply, e)
			}
		}
	}
	ctx := context.WithValue(context.WithValue(context.WithValue(f.p.ctx, profileContextKey{}, f.p), profileReceiptKey{}, receipt), profileGrantKey{}, parent)
	ctx = ProfileBootstrapRawContext(ctx, true)
	creates, sends, closes, joins := 0, 0, 0, 0
	f.p.datagramIO = func(d *profileBootstrapDatagramPermission) (*profileDNSOwnedSocket, error) {
		creates++
		if !f.c.datagramPermissionLive(d) || d.target.address != "203.0.113.80" || d.target.port != 8443 || d.target.network != 17 {
			return nil, fmt.Errorf("UDP member/parent conjunction")
		}
		life, cancel := context.WithCancel(d.context())
		return &profileDNSOwnedSocket{ctx: life, cancel: cancel, destination: d.target, gateIO: func() error {
			f.c.mu.Lock()
			defer f.c.mu.Unlock()
			if !f.c.datagramPermissionLive(d) {
				return errProfile
			}
			return nil
		},
			writeIO: func(b []byte) (int, error) { sends++; return len(b), nil }, readIO: func([]byte) (int, error) { return 0, io.EOF }, closeFD: func() error { closes++; return nil }}, nil
	}
	done := make(chan error, 1)
	go func() {
		if e := ProfilePrepareChain(ctx, nil); e != nil {
			done <- e
			return
		}
		frontier, _, err := f.c.hostsParentFrontier(parent)
		if err != nil {
			done <- err
			return
		}
		permission := f.c.datagramForGrant(parent)
		if cancelParent {
			f.c.mu.Lock()
			f.c.closeGrant(parent)
			f.c.mu.Unlock()
		}
		if consume != nil {
			e := consume(ctx, profileNumericDestination(frontier.target), profileNumericDestination(receipt.original))
			if e == nil || replay {
				s := permission.conn
				if s == nil || !s.managedStarted || !s.closing || s.readActive || s.writeActive {
					done <- fmt.Errorf("SS tasks/Close did not join")
					return
				}
				joins += 2
			}
			if replay {
				if _, _, again := ProfileDialBootstrapDatagram(ctx, profileNumericDestination(frontier.target)); again == nil {
					done <- fmt.Errorf("second SS open allowed")
					return
				}
			}
			done <- e
			return
		}
		conn, handled, e := ProfileDialBootstrapDatagram(ctx, profileNumericDestination(frontier.target))
		if !handled {
			done <- fmt.Errorf("unhandled SS UDP")
			return
		}
		if e != nil {
			done <- e
			return
		}
		if e = ProfileBindBootstrapDatagramContext(ctx, conn); e != nil {
			done <- e
			return
		}
		e = ProfileRunBootstrapDatagramTasks(ctx, conn, func() error { _, e := conn.Write([]byte("SS ciphertext")); return e }, func() error {
			_, e := conn.Read(make([]byte, 1))
			if e == io.EOF {
				return nil
			}
			return e
		})
		joins += 2
		if replay {
			if _, e2 := conn.Write([]byte("second")); e2 == nil {
				done <- fmt.Errorf("second send allowed")
				return
			}
			if _, _, e2 := ProfileDialBootstrapDatagram(ctx, profileNumericDestination(frontier.target)); e2 == nil {
				done <- fmt.Errorf("second open allowed")
				return
			}
		}
		ce := conn.Close()
		if e == nil {
			e = ce
		}
		done <- e
	}()
	deadline := time.After(3 * time.Second)
	for running := true; running; {
		select {
		case op := <-f.p.flowQueue:
			if e = f.c.dispatch(op); e != nil {
				t.Fatal("dispatch", op.kind, e)
			}
			accept()
		case e = <-done:
			if (e != nil) != (foreign || cancelParent || replay || badQuestion) {
				t.Fatal("actual SS consuming path", e)
			}
			running = false
		case <-deadline:
			t.Fatal("actor deadline")
		}
	}
	h := f.c.hostsObservations[0]
	f.c.mu.Lock()
	if network {
		f.c.networkBootstrapClose(f.c.networkBootstraps[0])
	} else {
		f.c.hostsObservationClose(h)
	}
	f.c.mu.Unlock()
	if network {
		n := f.c.networkBootstraps[0]
		if n.result != nil && n.result.networkConn != nil {
			if e = n.result.networkConn.Close(); e != nil {
				t.Fatal("DNS consuming close", e)
			}
		}
	}
	for i := 0; i < 64; i++ {
		if e = f.c.tick(); e != nil {
			t.Fatal("cleanup", e)
		}
		accept()
		if held != nil {
			n := f.c.networkBootstraps[0]
			for j := 0; j < 3; j++ {
				if e = f.c.tick(); e != nil {
					t.Fatal(e)
				}
				accept()
			}
			if n.service.cancelSent || n.released || n.service.networkCleanupRefs != 1 || n.transport.released || f.c.dnsCleanupResult() == nil {
				t.Fatal("late Resource ACK lost custody")
			}
			if e = f.c.accept(*held); e != nil {
				t.Fatal("actual delayed Resource ACK", e)
			}
			pipe.emit(map[string]any{"event": map[string]any{"name": "ack_release", "target": 3, "id": u64(held.body, 8), "reply": held.reply}})
			held = nil
		}
	}
	expected := 1
	if foreign || cancelParent || badQuestion {
		expected = 0
	}
	if creates != expected || sends != expected || closes != expected || joins != expected*2 {
		t.Fatal("fake UDP consuming counts", creates, sends, closes, joins)
	}
	if network {
		n := f.c.networkBootstraps[0]
		if !n.released || n.unknown || n.context == nil || !n.context.released || !n.datagramParent.released || !badQuestion && (n.waiter == nil || !n.waiter.released) {
			t.Fatal("NETWORK custody not closed")
		}
		if n.transport.started != n.op.sent || n.peer.network != protocol || dnsLeaf.factories != 1 || dnsLeaf.writes != 1 || dnsLeaf.closes != 1 || !dnsLeaf.duplicate.closed {
			t.Fatal("DNS protocol/anchor/close", *dnsLeaf)
		}
		if lateAck && !delayed {
			t.Fatal("no actual delayed Resource ACK")
		}
		if badQuestion {
			for _, k := range kinds {
				if k == 40 || k == 42 {
					t.Fatal("bad question reached DATA/permission")
				}
			}
		}
	} else if !h.released || h.unknown || !h.context.released || h.context.unknown || h.bootstrap != nil && !h.bootstrap.context.released || f.c.datagramOwnsGrant(parent) {
		t.Fatal("UDP contexts/bindings retained")
	}
	for _, b := range f.c.datagramParents[:f.c.datagramParentUsed] {
		if !b.released || b.unknown {
			t.Fatal("missing actual cancel9 ACK")
		}
	}
	if f.c.operations != preseedOperations {
		t.Fatal("bootstrap operation custody not retired", f.c.operations, preseedOperations)
	}
	pipe.emit(map[string]any{"go_done": true, "datagram": true, "network": network, "resolver_protocol": protocol, "late_ack": delayed, "ss_consumer": consume != nil, "mode": r.mode, "attempts": creates, "sends": sends, "socket_closes": closes, "tasks_joined": joins, "cleanup": true, "kinds": kinds, "denied": foreign || cancelParent || badQuestion, "replay_rejected": replay, "preseed_operations": preseedOperations, "retained_operations": f.c.operations, "preseed_user_skipped": true})
}
