package use_forwaded_header

import (
	"fmt"
	"context"
	"net"
	"net/http"
	"strings"
)

type Config struct {
	ForHeader  string   `yaml:"forHeader"`
	TrustedIPs []string `yaml:"trustedIPs"`
}

func CreateConfig() *Config {
	return &Config{
		ForHeader: "X-Real-Ip",
	}
}

type Plugin struct {
	forHeader  string
	trustedIPs []*net.IPNet
	name       string
	next       http.Handler
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	trustedIPs := []*net.IPNet{}
	
	for _, cidr := range config.TrustedIPs {
		if !strings.Contains(cidr, "/") {
			cidr = cidr + "/32"
			if strings.Contains(cidr, ":") {
				cidr = cidr[:len(cidr)-3] + "/128"
			}
		}
		_, ipnet, err := net.ParseCIDR(cidr)
		if err == nil {
			trustedIPs = append(trustedIPs, ipnet)
		}
	}
	
	return &Plugin{
		forHeader:  strings.TrimSpace(config.ForHeader),
		trustedIPs: trustedIPs,
		name:       name,
		next:       next,
	}, nil
}

func (plugin *Plugin) ServeHTTP(rw http.ResponseWriter, req *http.Request) {

	req.Header.Set("X-Plugin-Debug", "UseForwardedHeader-Running")
	
	remoteIP, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		remoteIP = req.RemoteAddr  // Sem porta
	}

	req.Header.Set("X-Debug-RemoteAddr", req.RemoteAddr)
	req.Header.Set("X-Debug-RemoteIP", remoteIP)

	ip := net.ParseIP(remoteIP)

	trusted := false
	if ip != nil {
		for _, ipnet := range plugin.trustedIPs {
			if ipnet.Contains(ip) {
				trusted = true
				break
			}
		}
	}

	req.Header.Set("X-Debug-Trusted", fmt.Sprintf("%v", trusted))
	req.Header.Set("X-Debug-IP-Parsed", fmt.Sprintf("%v", ip != nil))
	
	if !trusted {
		plugin.next.ServeHTTP(rw, req)
		return
	}

	Forwarded := []string{}
	For := strings.TrimSpace(req.Header.Get(plugin.forHeader))
	Host := strings.TrimSpace(req.Header.Get("X-Forwarded-Host"))
	Proto := strings.TrimSpace(req.Header.Get("X-Forwarded-Proto"))

	if len(For) > 0 {
		if strings.Contains(For, ":") && !strings.HasPrefix(For, "[") {
			For = "[" + For + "]"
		}
		Forwarded = append(Forwarded, "for="+For)
	}
	
	if len(Host) > 0 {
		Forwarded = append(Forwarded, "host="+Host)
	}
	
	if len(Proto) > 0 {
		Forwarded = append(Forwarded, "proto="+Proto)
	}

	if len(Forwarded) > 0 {
		req.Header.Set("Forwarded", strings.Join(Forwarded, ";"))
	}
	
	plugin.next.ServeHTTP(rw, req)
}