//go:build yonikpureinterop

// Новый tagged test member, никогда не включается в production adapter.
package shadowsocks

import (
	"context"
	"fmt"
	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	nativehooks "github.com/xtls/xray-core/common/yonikbroker"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/transport"
	"io"
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
