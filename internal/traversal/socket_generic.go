//go:build !linux

package traversal

import (
	"errors"
	"net/netip"
)

// ErrUnsupportedPlatform reports platform-specific functionality that v1
// does not claim on the current OS. Linux route/source selection is native
// Linux evidence only (v0.8: no Windows/arm64 runtime claims without native
// evidence; cross-builds are compile checks, not capability).
var ErrUnsupportedPlatform = errors.New("traversal: IPv4 route/source selection unsupported on this platform")

// HostRouteTable exists on every platform so the traversal API compiles, but
// only Linux reads real routing state.
type HostRouteTable struct{}

func (HostRouteTable) DefaultRouteV4() (netip.Addr, string, bool, error) {
	return netip.Addr{}, "", false, ErrUnsupportedPlatform
}

func (HostRouteTable) IPv4Addresses() ([]IPv4Address, error) {
	return nil, ErrUnsupportedPlatform
}
