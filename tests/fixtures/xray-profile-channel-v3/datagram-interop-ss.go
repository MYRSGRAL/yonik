//go:build yonikpureinterop

// Новый tagged test member, никогда не включается в production adapter.
package shadowsocks

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	nativehooks "github.com/xtls/xray-core/common/yonikbroker"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/stat"
	"io"
	stdnet "net"
	"os"
	"strings"
	"time"
)

type interopPolicy struct{}

func (interopPolicy) Type() interface{} { return policy.ManagerType() }
func (interopPolicy) Start() error      { return nil }
func (interopPolicy) Close() error      { return nil }
func (interopPolicy) ForLevel(uint32) policy.Session {
	return policy.Session{Timeouts: policy.Timeout{ConnectionIdle: time.Minute, UplinkOnly: time.Minute, DownlinkOnly: time.Minute}}
}

type franceDialer struct {
	dial func(context.Context, xnet.Destination) (stdnet.Conn, error)
}

func (d franceDialer) Dial(ctx context.Context, dest xnet.Destination) (stat.Connection, error) {
	// Native dial/stream/dual-authority guards сохранены; подменён только raw IO.
	if e := nativehooks.ProfileCheckDial(ctx, dest, false); e != nil {
		return nil, e
	}
	if e := nativehooks.ProfileCheckTransport(ctx, 1); e != nil {
		return nil, e
	}
	return nativehooks.ProfileDialBootstrap(ctx, dest, d.dial)
}
func (franceDialer) DestIpAddress() xnet.IP                                { return nil }
func (franceDialer) SetOutboundGateway(context.Context, *session.Outbound) {}

type franceTCPReader struct {
	ctx    context.Context
	count  int
	resume <-chan struct{}
	eof    chan<- struct{}
}

func (r *franceTCPReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	if r.count == 2 {
		close(r.eof)
		r.count++
		return nil, io.EOF
	}
	if r.count > 2 {
		return nil, io.EOF
	}
	if r.count == 1 {
		select {
		case <-r.resume:
		case <-r.ctx.Done():
			return nil, r.ctx.Err()
		}
	}
	r.count++
	b := buf.New()
	b.Write([]byte{0x11, 0x22})
	return buf.MultiBuffer{b}, nil
}

// Config — exact compiled FranceSS из Rust. Ни core.New, ни NewClient, ни sockets.
// Policy/link/dialer — leaf injections; Client.Process/SS crypto/tasks — production.
func PureInteropConsumeFrance(ctx context.Context, config []byte, original xnet.Destination, dial func(context.Context, xnet.Destination) (stdnet.Conn, error), resume <-chan struct{}, eof chan<- struct{}) error {
	var c struct {
		Outbounds []struct {
			Tag, Protocol string
			Settings      struct {
				Servers []struct {
					Address, Method, Password string
					Port                      uint16
				}
			}
		}
	}
	if e := json.Unmarshal(config, &c); e != nil {
		return e
	}
	for _, o := range c.Outbounds {
		if o.Tag != "proxy" {
			continue
		}
		if o.Protocol != "shadowsocks" || len(o.Settings.Servers) != 1 {
			return fmt.Errorf("full France settings changed")
		}
		s := o.Settings.Servers[0]
		if s.Address != "fr.example.invalid" || s.Port != 443 || s.Method != "aes-128-gcm" || s.Password != "synthetic-password" {
			return fmt.Errorf("exact imported SS server")
		}
		account, e := (&Account{CipherType: CipherType_AES_128_GCM, Password: s.Password}).AsAccount()
		if e != nil {
			return e
		}
		server := xnet.TCPDestination(xnet.DomainAddress(s.Address), xnet.Port(s.Port))
		client := &Client{server: protocol.NewServerSpec(server, &protocol.MemoryUser{Account: account}), policyManager: interopPolicy{}}
		ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{Target: original}})
		ctx = nativehooks.ProfileBootstrapRawContext(ctx, client.ProfileBootstrapDatagramSource())
		var reader buf.Reader = &interopPacket{twice: strings.HasSuffix(os.Getenv("YONIK_INTEROP_CASE"), "second-send")}
		if original.Network == xnet.Network_TCP {
			reader = &franceTCPReader{ctx: ctx, resume: resume, eof: eof}
		}
		return client.Process(ctx, &transport.Link{Reader: reader, Writer: &interopWriter{}}, franceDialer{dial: dial})
	}
	return fmt.Errorf("missing imported FranceSS outbound")
}
func (interopPolicy) ForSystem() policy.System { return policy.System{} }

type interopPacket struct {
	count int
	twice bool
}

func (r *interopPacket) ReadMultiBuffer() (buf.MultiBuffer, error) {
	if r.count == 2 || r.count == 1 && !r.twice {
		return nil, io.EOF
	}
	r.count++
	b := buf.New()
	b.Write([]byte{0xaa, 0xbb})
	return buf.MultiBuffer{b}, nil
}

type interopWriter struct{}

func (*interopWriter) WriteMultiBuffer(b buf.MultiBuffer) error { buf.ReleaseMulti(b); return nil }
func (*interopWriter) Close() error                             { return nil }

// Только leaf constructor policy/link: actual Process/UDP encoding/managed tasks.
// Не вызывает core.New, NewClient, socket factory или internet.Dialer.
func PureInteropConsumeDatagram(ctx context.Context, server, original xnet.Destination) error {
	account, e := (&Account{CipherType: CipherType_AES_128_GCM, Password: "pure-fixture"}).AsAccount()
	if e != nil {
		return e
	}
	client := &Client{server: protocol.NewServerSpec(server, &protocol.MemoryUser{Account: account}), policyManager: interopPolicy{}}
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{Target: original}})
	ctx = nativehooks.ProfileBootstrapRawContext(ctx, client.ProfileBootstrapDatagramSource())
	replay := strings.HasSuffix(os.Getenv("YONIK_INTEROP_CASE"), "replay")
	reader := &interopPacket{twice: replay}
	err := client.Process(ctx, &transport.Link{Reader: reader, Writer: &interopWriter{}}, nil)
	if replay && (reader.count != 2 || err == nil) {
		return fmt.Errorf("actual SS second packet not rejected")
	}
	return err
}
