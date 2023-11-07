package authflow

import (
	"net"
	"net/http"
	"net/netip"

	"github.com/dexidp/dex/server/reqctx"
)

// connectorIPAllowed controls which connectors appear in the login selection.
// Forwarded addresses must come from the router's trusted-proxy resolver.
func connectorIPAllowed(r *http.Request, whitelist []string) bool {
	if len(whitelist) == 0 {
		return true
	}
	ip, _ := r.Context().Value(reqctx.RequestKeyRemoteIP).(string)
	if ip == "" {
		ip, _, _ = net.SplitHostPort(r.RemoteAddr)
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	for _, allowed := range whitelist {
		if candidate, err := netip.ParseAddr(allowed); err == nil && candidate.Unmap() == addr.Unmap() {
			return true
		}
	}
	return false
}
