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
	"net"
	"os"
	"testing"
	"time"
)

// Только transport overlay; ни одной production source строки не заменяет.
type interopPipe struct {
	t      *testing.T
	scan   *bufio.Scanner
	launch profileLaunch
	rx     uint64
	tx     uint64
}

func (p *interopPipe) read() map[string]json.RawMessage {
	if !p.scan.Scan() {
		p.t.Fatal("relay EOF", p.scan.Err())
	}
	var v map[string]json.RawMessage
	if e := json.Unmarshal(p.scan.Bytes(), &v); e != nil {
		p.t.Fatal(e)
	}
	return v
}
func (p *interopPipe) bytes(v json.RawMessage) []byte {
	var s string
	if e := json.Unmarshal(v, &s); e != nil {
		p.t.Fatal(e)
	}
	b, e := hex.DecodeString(s)
	if e != nil {
		p.t.Fatal(e)
	}
	return b
}
func (p *interopPipe) emit(v any) {
	b, e := json.Marshal(v)
	if e != nil {
		p.t.Fatal(e)
	}
	fmt.Println(string(b))
}
func (p *interopPipe) packet() []byte { return p.bytes(p.read()["packet"]) }
func (p *interopPipe) send(kind uint16, reply uint64, body []byte) error {
	// HELLO уже принят trusted peer seam перед Rust run_issuer; не fake ACK.
	if kind == 1 {
		return nil
	}
	p.tx++
	p.emit(map[string]any{"packet": hex.EncodeToString(p.launch.packet(kind, p.tx, reply, body))})
	return nil
}
func (p *interopPipe) receive(time.Time) ([]byte, error) { return p.packet(), nil }

func TestPureStatefulHostsStdioBridge(t *testing.T) {
	if os.Getenv("YONIK_PURE_INTEROP") == "" {
		t.Skip("только bounded orchestrator")
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
	now := time.Now()
	admission, e := admitProfile(r, decode(init.Config), pipe, func(m *profileCapsule) error {
		asset := snapshotAsset(snapshot)
		row := m.rows[10][0]
		if !bytes.Equal(asset.source[:], row[:32]) || !bytes.Equal(asset.digest[:], row[32:64]) || asset.size != uint64(u32(row, 64)) {
			return errProfile
		}
		_, e := decodeProfileSnapshot(snapshot, snapshotAsset(snapshot))
		return e
	}, func() time.Time { return now })
	if e != nil {
		t.Fatal("admission", e)
	}
	pipe.rx = 1
	f := newFlowFixture(t, r.mode)
	receipt := f.admittedReceipt(t, "parent.invalid")
	parent := f.granted(t, receipt)
	if parent.id != init.User.Grant || receipt.id != init.User.Flow || parent.revision != init.User.Revision || parent.ownerKind != init.User.OwnerKind || parent.ownerID != init.User.OwnerID || parent.ownerDeadline.Sub(f.now) != time.Duration(init.User.KnownNS) && r.mode == 2 {
		t.Fatal("common USER preseed mismatch")
	}
	// Единственный пропущенный policy path — preseed исходного USER parent.
	// Все HOSTS ACK ниже поступают от другого SUT, без reply fixture helpers.
	f.p.admission = admission
	alive := f.c.alive
	proofAlive := f.c.proofAlive
	f.c = newProfileFlowControl(admission.capsule, r.mode, func() time.Time { return f.now }, nil, alive)
	f.c.proofAlive = proofAlive
	if f.p.proofs != nil {
		f.p.proofs.launch = r
	}
	f.p.flow = f.c
	receipt.control = f.c
	f.c.receipts[receipt.slot] = receipt
	f.c.grants[parent.slot] = parent
	f.c.highestFlow = receipt.id
	f.c.highestGrant = parent.id
	f.p.snapshot, e = decodeProfileSnapshot(snapshot, snapshotAsset(snapshot))
	if e != nil {
		t.Fatal(e)
	}
	f.c.nextDNSQuery = 8
	parent.subject = init.Subject
	parent.scope = init.Path[0][0]
	parent.branch = byte(init.Path[0][1])
	parent.revision = f.c.manifest.policy
	scope := f.c.manifest.rows[8][parent.scope]
	parent.stream = u16(scope, 12)
	parent.chain = u16(scope, 16)
	receipt.revision = f.c.manifest.policy
	f.sequence = 2
	ops := profileDNSSetupOps{now: func() time.Time { return f.now }, alive: func() bool { return true }, reject: func(profileProofPacket) error { return nil }}
	ops.send = func(b []byte) error { pipe.emit(map[string]any{"packet": hex.EncodeToString(b)}); return nil }
	ops.receive = func(time.Time) (profileProofPacket, error) {
		uid := uint32(1000)
		if r.mode == 2 {
			uid = 0
		}
		return profileProofPacket{body: pipe.packet(), credentials: 1, pid: int32(r.hostPID), uid: uid}, nil
	}
	if e = f.p.setupDNSV2(launch, f.now.Add(time.Second), 1000, ops); e != nil {
		t.Fatal("setup", e)
	}
	var replies []profilePacket
	kinds := []uint16{}
	foreign := os.Getenv("YONIK_INTEROP_CASE") == "foreign-member"
	expired := os.Getenv("YONIK_INTEROP_CASE") == "system-parent-expired"
	f.c.write = func(kind uint16, object uint64, body []byte) (uint64, error) {
		f.sequence++
		seq := f.sequence
		kinds = append(kinds, kind)
		var raw []byte
		if foreign && kind == 42 {
			body = append([]byte(nil), body...)
			body[len(body)-1] ^= 1
		}
		if profileDNSV2Operation(kind) {
			raw = make([]byte, 65536)
			n, e := profileDNSV2Encode(r, kind, seq, 0, body, raw)
			if e != nil {
				return 0, e
			}
			raw = raw[:n]
		} else {
			raw = r.packet(kind, seq, 0, body)
			be.PutUint64(raw[112:], object)
		}
		pipe.emit(map[string]any{"packet": hex.EncodeToString(raw)})
		response := pipe.packet()
		pipe.rx++
		packet, e := r.decodePacket(response, pipe.rx)
		if e != nil {
			return 0, e
		}
		if profileDNSV2Operation(packet.kind) && !profileDNSV2Envelope(r, response, true, 0, 0, seq) {
			return 0, errProfile
		}
		replies = append(replies, packet)
		return seq, nil
	}
	accept := func() {
		for len(replies) > 0 {
			reply := replies[0]
			replies = replies[1:]
			if e := f.c.accept(reply); e != nil {
				t.Fatalf("accept kind%d reply%d: %v", reply.kind, reply.reply, e)
			}
		}
	}
	ctx := context.WithValue(context.WithValue(context.WithValue(f.p.ctx, profileContextKey{}, f.p), profileReceiptKey{}, receipt), profileGrantKey{}, parent)
	ctx = ProfileBootstrapRawContext(ctx, true)
	done := make(chan error, 1)
	parentReady := make(chan struct{}, 1)
	allowOpen := make(chan struct{})
	permissionBeforeExpiry := false
	attempts := 0
	go func() {
		if err := ProfilePrepareChain(ctx, nil); err != nil {
			done <- err
			return
		}
		frontier, _, err := f.c.hostsParentFrontier(parent)
		if err != nil {
			done <- err
			return
		}
		if expired {
			parentReady <- struct{}{}
			select {
			case <-allowOpen:
			case <-ctx.Done():
				done <- ctx.Err()
				return
			}
		}
		conn, err := ProfileDialBootstrap(ctx, profileNumericDestination(frontier.target), func(callback context.Context, numeric xnet.Destination) (net.Conn, error) {
			attempts++
			if ProfilePhysicalGate(callback) != nil || numeric.Address.String() != "203.0.113.80" || numeric.Port != 8443 {
				return nil, fmt.Errorf("dual authority/endpoint")
			}
			return &flowFakeConn{}, nil
		})
		if err == nil {
			err = conn.Close()
		}
		done <- err
	}()
	deadline := time.After(3 * time.Second)
	running := true
	for running {
		select {
		case <-parentReady:
			f.c.mu.Lock()
			h := f.c.hostsObservations[0]
			permissionBeforeExpiry = h != nil && h.bootstrap != nil && h.bootstrap.permission != nil && f.c.bootstrapPermissionLive(h.bootstrap.permission) && f.c.dnsSourceCapabilityLive(h.bootstrap.context, h.bootstrap.context.capability) && f.c.grantLive(parent)
			if !permissionBeforeExpiry || r.mode != 2 || init.User.KnownNS != uint64(20*time.Millisecond) {
				f.c.mu.Unlock()
				t.Fatal("missing live System conjunction before expiry")
			}
			// Никакой wallclock задержки: истекает исходный Known, не новый lease.
			f.now = f.now.Add(time.Duration(init.User.KnownNS))
			if f.now.Before(parent.ownerDeadline) {
				f.c.mu.Unlock()
				t.Fatal("Known did not expire")
			}
			f.c.mu.Unlock()
			close(allowOpen)
		case op := <-f.p.flowQueue:
			if op.kind == 42 {
				frontier, _, err := f.c.hostsParentFrontier(parent)
				if err != nil {
					t.Fatal(err)
				}
				_, err = ProfileDialBootstrap(ctx, profileNumericDestination(frontier.target), func(context.Context, xnet.Destination) (net.Conn, error) { attempts++; return &flowFakeConn{}, nil })
				if err == nil || attempts != 0 {
					t.Fatal("factory before permission")
				}
			}
			if e := f.c.dispatch(op); e != nil {
				t.Fatalf("dispatch kind%d: %v", op.kind, e)
			}
			accept()
		case err := <-done:
			if (err != nil) != (foreign || expired) {
				t.Fatal("actual caller", err)
			}
			running = false
		case <-deadline:
			t.Fatal("actor deadline")
		}
	}
	expected := 1
	if foreign || expired {
		expected = 0
	}
	if attempts != expected {
		t.Fatal("physical attempts", attempts)
	}
	h := f.c.hostsObservations[0]
	f.c.mu.Lock()
	f.c.hostsObservationClose(h)
	f.c.mu.Unlock()
	// Cleanup ACKs также выдаёт Rust actor, не test-only synthesized replies.
	for i := 0; i < 16; i++ {
		if e := f.c.dnsTick(); e != nil {
			t.Fatal("cleanup", e)
		}
		accept()
	}
	if h == nil || !h.released || !h.context.released || !h.bootstrap.context.released || h.unknown || h.context.unknown || f.c.operations != 0 {
		t.Fatal("cleanup custody not KnownClosed")
	}
	pipe.emit(map[string]any{"go_done": true, "attempts": attempts, "kinds": kinds, "cleanup": true, "denied": foreign || expired, "mode": r.mode, "parent_expired": expired, "permission_before_expiry": permissionBeforeExpiry})
}
