package server

import (
	"net"
	"net/http"
	"strings"
)

func readUserIP(r *http.Request) string {
	IPAddress := r.Header.Get("X-Real-Ip")
	if IPAddress == "" {
		IPAddress = r.Header.Get("X-Forwarded-For")
	}
	if IPAddress == "" {
		if strings.ContainsRune(r.RemoteAddr, ':') {
			IPAddress, _, _ = net.SplitHostPort(r.RemoteAddr)
		} else {
			IPAddress = r.RemoteAddr
		}
	}
	return IPAddress
}
