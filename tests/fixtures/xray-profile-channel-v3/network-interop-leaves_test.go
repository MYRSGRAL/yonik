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
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
func interopNetworkIO(t *testing.T, f *flowFixture, pipe *interopPipe, bad bool, receive func(uint64) error, proofEvent func()) *interopDNSLeaf {
	leaf := &interopDNSLeaf{duplicate: &proofFakeFD{}}
	f.p.dnsID = func() uint16 { return 0x1234 }
	f.p.dnsDirectIO = &profileDNSDirectIO{
		create: func(ctx context.Context, want profileDestinationValue) (*profileDNSOwnedSocket, error) {
			if !ProfileDNSDirectFactory(ctx) || want.address != "192.0.2.53" || want.port != 53 || want.network != 17 {
				return nil, errProfile
			}
			leaf.factories++
			owner := ctx.Value(profileDNSFactoryKey{}).(*profileDNSDirect)
			life, cancel := context.WithCancel(owner.ctx)
			var response *bytes.Reader
			socket := &profileDNSOwnedSocket{ctx: life, cancel: cancel, destination: want, fd: &proofFakeFD{}, waitIO: func(context.Context, bool, time.Time) error { return errProfile }}
			socket.writeIO = func(raw []byte) (int, error) {
				leaf.writes++
				var m dnsmessage.Message
				if m.Unpack(raw) != nil || len(m.Questions) != 1 || m.Questions[0].Name.String() != "physical.invalid." {
					return 0, errProfile
				}
				m.Response = true
				m.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: m.Questions[0].Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 30}, Body: &dnsmessage.AResource{A: [4]byte{203, 0, 113, 80}}}}
				if bad {
					m.Questions[0].Name, _ = dnsmessage.NewName("foreign.invalid.")
				}
				reply, err := m.Pack()
				if err != nil {
					return 0, err
				}
				response = bytes.NewReader(reply)
				return len(raw), nil
			}
			socket.readIO = func(b []byte) (int, error) {
				if response == nil {
					return 0, errProfile
				}
				return response.Read(b)
			}
			socket.closeFD = func() error { leaf.closes++; return nil }
			leaf.socket = socket
			return socket, nil
		},
		duplicate: func(s *profileDNSOwnedSocket, want profileDestinationValue) (profileProofFD, error) {
			if s != leaf.socket || want != s.destination {
				return nil, errProfile
			}
			return leaf.duplicate, nil
		},
		send: func(raw []byte, fd profileProofFD) error {
			if fd != leaf.duplicate || !profileDNSV2Envelope(f.p.admission.launch, raw, false, 1, 1, 0) {
				return errProfile
			}
			proofEvent()
			pipe.emit(map[string]any{"physical": hex.EncodeToString(raw)})
			return receive(f.sequence)
		},
	}
	t.Cleanup(func() {
		if leaf.socket != nil {
			_ = leaf.socket.Close()
		}
	})
	return leaf
}
