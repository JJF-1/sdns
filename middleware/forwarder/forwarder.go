package forwarder

import (
	"context"
	"crypto/tls"
	"net"
	"strconv"
	"strings"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/sdns/util"
	"github.com/semihalev/zlog/v2"
)

type server struct {
	Addr  string
	Proto string
	Name  string
}

// Forwarder type.
type Forwarder struct {
	servers   []*server
	dnssec    bool
	tlsConfig *tls.Config
}

// New return forwarder.
func New(cfg *config.Config) *Forwarder {
	forwarderservers := []*server{}
	for _, s := range cfg.ForwarderServers {
		srv := &server{Proto: "udp"}
		raw := s

		if strings.HasPrefix(s, "tls://") {
			s = strings.TrimPrefix(s, "tls://")
			srv.Proto = "tcp-tls"
		}

		host, port, err := net.SplitHostPort(s)
		if err != nil {
			zlog.Error("Forwarder server is not correct. Check your config.", "server", raw)
			continue
		}

		parsedPort, err := strconv.Atoi(port)
		if err != nil || parsedPort <= 0 || parsedPort > 65535 {
			zlog.Error("Forwarder server is not correct. Check your config.", "server", raw)
			continue
		}

		if ip := net.ParseIP(host); ip != nil {
			srv.Addr = net.JoinHostPort(host, port)
			forwarderservers = append(forwarderservers, srv)
			continue
		}

		host = strings.TrimSuffix(host, ".")
		if !validDomainName(host) {
			zlog.Error("Forwarder server is not correct. Check your config.", "server", raw)
			continue
		}

		srv.Addr = net.JoinHostPort(host, port)
		srv.Name = host
		forwarderservers = append(forwarderservers, srv)
	}

	return &Forwarder{servers: forwarderservers, dnssec: cfg.DNSSEC == "on"}
}

// (*Forwarder).Name name return middleware name.
func (f *Forwarder) Name() string { return name }

// (*Forwarder).ServeDNS serveDNS implements the Handle interface.
func (f *Forwarder) ServeDNS(ctx context.Context, ch *middleware.Chain) {
	w, req := ch.Writer, ch.Request

	if len(req.Question) == 0 || len(f.servers) == 0 {
		ch.CancelWithRcode(dns.RcodeServerFailure, true)
		return
	}

	// Preserve the client's CD bit. We may set CD=1 on the
	// upstream query when this server isn't doing DNSSEC, but
	// the response written back to the client must reflect
	// what the client asked for — otherwise the cache dedup
	// key (CD=client) and the stored entry's CD diverge, and
	// CD=1 clients re-miss every lookup in forwarder mode.
	clientCD := req.CheckingDisabled
	if !clientCD && !f.dnssec {
		req.CheckingDisabled = true
	}
	defer func() { req.CheckingDisabled = clientCD }()

	for _, server := range f.servers {
		reqClient := &dns.Client{Net: server.Proto}
		if server.Proto == "tcp-tls" {
			if f.tlsConfig != nil {
				reqClient.TLSConfig = f.tlsConfig.Clone()
			}
			if server.Name != "" {
				if reqClient.TLSConfig == nil {
					reqClient.TLSConfig = &tls.Config{}
				}
				if reqClient.TLSConfig.ServerName == "" {
					reqClient.TLSConfig.ServerName = server.Name
				}
			}
		}

		resp, err := util.Exchange(ctx, req, server.Addr, server.Proto, reqClient)
		if err != nil {
			zlog.Info("forwarder query failed", "query", formatQuestion(req.Question[0]), "error", err.Error())
			continue
		}

		// Reject responses whose question section does not match the
		// outstanding query. A malicious or misbehaving upstream that
		// returns a different name/type/class would otherwise be cached
		// under that question, poisoning lookups for unrelated names.
		if !questionMatches(req.Question[0], resp.Question) {
			zlog.Info("forwarder dropped response with mismatched question",
				"query", formatQuestion(req.Question[0]))
			continue
		}

		resp.Id = req.Id
		resp.CheckingDisabled = clientCD

		_ = w.WriteMsg(resp)
		return
	}

	// Restore the client's CD before synthesising the
	// all-upstreams-failed SERVFAIL. CancelWithRcode calls
	// SetReply under the hood, which copies
	// req.CheckingDisabled into the response; leaving the
	// overridden CD in place would hand the cache a SERVFAIL
	// stored under CD=true while the lookup keyed on CD=false.
	// The deferred restore above still covers the early
	// return on success.
	req.CheckingDisabled = clientCD
	ch.CancelWithRcode(dns.RcodeServerFailure, true)
}

func formatQuestion(q dns.Question) string {
	return strings.ToLower(q.Name) + " " + dns.ClassToString[q.Qclass] + " " + dns.TypeToString[q.Qtype]
}

// questionMatches reports whether the response's question section answers the
// outstanding request question. The name comparison is case-insensitive
// because DNS names are not case-sensitive on the wire.
func questionMatches(req dns.Question, resp []dns.Question) bool {
	if len(resp) != 1 {
		return false
	}
	r := resp[0]
	return r.Qtype == req.Qtype && r.Qclass == req.Qclass && strings.EqualFold(r.Name, req.Name)
}

func validDomainName(host string) bool {
	if host == "" || len(host) > 253 {
		return false
	}

	labels := strings.Split(host, ".")
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		if !isASCIILetterDigit(label[0]) || !isASCIILetterDigit(label[len(label)-1]) {
			return false
		}
		for i := 1; i < len(label)-1; i++ {
			if isASCIILetterDigit(label[i]) || label[i] == '-' {
				continue
			}
			return false
		}
	}

	return true
}

func isASCIILetterDigit(c byte) bool {
	return (c >= 'a' && c <= 'z') ||
		(c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9')
}

const name = "forwarder"
