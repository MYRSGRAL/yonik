//go:build linux

package nativehooks

import (
	"bytes"
	"context"
	"encoding/hex"
	"golang.org/x/net/dns/dnsmessage"
	"testing"
	"time"
)

// Только leaf IO: consuming socket owner, private exchange, dispatcher и все
// ACK barriers исполняются production code. Ни один syscall не вызывается.
type interopDNSLeaf struct {
	factories, writes, closes int
	duplicate                 *proofFakeFD
	socket                    *profileDNSOwnedSocket
	// Два фиксированных слота резервируются до create, без общего last-exchange.
	entries [2]interopDNSExchange
	used    int
}
type interopDNSExchange struct {
	socket    *profileDNSOwnedSocket
	duplicate *proofFakeFD
	sent      bool
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
func interopNetworkIO(t *testing.T, f *flowFixture, pipe *interopPipe, bad bool, receive func(uint64) error, proofEvent func()) *interopDNSLeaf {
	return interopNetworkProtocolIO(t, f, pipe, bad, 17, receive, proofEvent)
}
func interopNetworkProtocolIO(t *testing.T, f *flowFixture, pipe *interopPipe, bad bool, protocol byte, receive func(uint64) error, proofEvent func()) *interopDNSLeaf {
	return interopNetworkOwnedIO(t, f, pipe, protocol, "physical.invalid.", 1, func(int) bool { return bad }, receive, proofEvent)
}
func interopNetworkOwnedIO(t *testing.T, f *flowFixture, pipe *interopPipe, protocol byte, hostname string, limit int, bad func(int) bool, receive func(uint64) error, proofEvent func()) *interopDNSLeaf {
	leaf := &interopDNSLeaf{duplicate: &proofFakeFD{}}
	f.p.dnsID = func() uint16 { return 0x1234 }
	f.p.dnsDirectIO = &profileDNSDirectIO{
		create: func(ctx context.Context, want profileDestinationValue) (*profileDNSOwnedSocket, error) {
			if limit < 1 || limit > len(leaf.entries) || leaf.used >= limit || !ProfileDNSDirectFactory(ctx) || want.address != "192.0.2.53" || want.port != 53 || want.network != protocol {
				return nil, errProfile
			}
			index := leaf.used
			entry := &leaf.entries[index]
			leaf.used++
			entry.duplicate = &proofFakeFD{}
			leaf.factories++
			owner := ctx.Value(profileDNSFactoryKey{}).(*profileDNSDirect)
			life, cancel := context.WithCancel(owner.ctx)
			var response *bytes.Reader
			socket := &profileDNSOwnedSocket{ctx: life, cancel: cancel, destination: want, fd: &proofFakeFD{}, waitIO: func(context.Context, bool, time.Time) error { return errProfile }}
			socket.writeIO = func(raw []byte) (int, error) {
				leaf.writes++
				length := len(raw)
				if protocol == 6 {
					if len(raw) < 2 || int(be.Uint16(raw)) != len(raw)-2 {
						return 0, errProfile
					}
					raw = raw[2:]
				}
				var m dnsmessage.Message
				if m.Unpack(raw) != nil || len(m.Questions) != 1 || m.Questions[0].Name.String() != hostname {
					return 0, errProfile
				}
				m.Response = true
				m.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: m.Questions[0].Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 30}, Body: &dnsmessage.AResource{A: [4]byte{203, 0, 113, 80}}}}
				if bad(index) {
					m.Questions[0].Name, _ = dnsmessage.NewName("foreign.invalid.")
				}
				reply, err := m.Pack()
				if err != nil {
					return 0, err
				}
				if protocol == 6 {
					prefix := make([]byte, 2)
					be.PutUint16(prefix, uint16(len(reply)))
					reply = append(prefix, reply...)
				}
				response = bytes.NewReader(reply)
				return length, nil
			}
			socket.readIO = func(b []byte) (int, error) {
				if response == nil {
					return 0, errProfile
				}
				return response.Read(b)
			}
			socket.closeFD = func() error { leaf.closes++; return nil }
			leaf.socket = socket
			entry.socket = socket
			leaf.duplicate = entry.duplicate
			return socket, nil
		},
		duplicate: func(s *profileDNSOwnedSocket, want profileDestinationValue) (profileProofFD, error) {
			for i := 0; i < leaf.used; i++ {
				entry := &leaf.entries[i]
				if s == entry.socket && want == s.destination && !entry.sent {
					return entry.duplicate, nil
				}
			}
			return nil, errProfile
		},
		send: func(raw []byte, fd profileProofFD) error {
			var selected *interopDNSExchange
			for i := 0; i < leaf.used; i++ {
				if fd == leaf.entries[i].duplicate && !leaf.entries[i].sent {
					selected = &leaf.entries[i]
					break
				}
			}
			if selected == nil || !profileDNSV2Envelope(f.p.admission.launch, raw, false, 1, 1, 0) {
				return errProfile
			}
			selected.sent = true
			proofEvent()
			pipe.emit(map[string]any{"physical": hex.EncodeToString(raw)})
			return receive(f.sequence)
		},
	}
	t.Cleanup(func() {
		for i := 0; i < leaf.used; i++ {
			if leaf.entries[i].socket != nil {
				_ = leaf.entries[i].socket.Close()
			}
		}
	})
	return leaf
}
