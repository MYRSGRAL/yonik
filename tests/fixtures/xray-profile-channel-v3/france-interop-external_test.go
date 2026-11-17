//go:build linux && yonikpureinterop

package nativehooks_test

import (
	nativehooks "github.com/xtls/xray-core/common/yonikbroker"
	"github.com/xtls/xray-core/proxy/shadowsocks"
	"testing"
)

func TestPureStatefulFranceSSStdioBridge(t *testing.T) {
	nativehooks.RunPureFranceSession(t, shadowsocks.PureInteropConsumeFrance)
}
