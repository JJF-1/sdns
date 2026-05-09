package failover

import (
	"context"
	"net"
	"testing"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/sdns/mock"
	"github.com/semihalev/zlog/v2"
	"github.com/stretchr/testify/assert"
)

type dummy struct{}

func (d *dummy) ServeDNS(ctx context.Context, ch *middleware.Chain) {
	w, req := ch.Writer, ch.Request

	m := new(dns.Msg)
	m.SetRcode(req, dns.RcodeServerFailure)

	_ = w.WriteMsg(m)
}

func (d *dummy) Name() string { return "dummy" }

func Test_Failover(t *testing.T) {
	logger := zlog.NewStructured()
	logger.SetWriter(zlog.StdoutTerminal())
	logger.SetLevel(zlog.LevelDebug)
	zlog.SetDefault(logger)

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	assert.NoError(t, err)
	t.Cleanup(func() { _ = pc.Close() })

	srv := &dns.Server{
		PacketConn: pc,
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			m := new(dns.Msg)
			m.SetReply(r)

			if len(r.Question) > 0 && r.Question[0].Qtype == dns.TypeA {
				m.Answer = append(m.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
					A:   net.IPv4(127, 0, 0, 1),
				})
			}

			_ = w.WriteMsg(m)
		}),
	}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })

	cfg := new(config.Config)
	cfg.FallbackServers = []string{pc.LocalAddr().String(), "1"}

	middleware.Register("failover", func(cfg *config.Config) middleware.Handler { return New(cfg) })
	middleware.Setup(cfg)

	f := middleware.Get("failover").(*Failover)
	assert.Equal(t, "failover", f.Name())

	ch := middleware.NewChain([]middleware.Handler{f, &dummy{}})

	ctx := context.Background()

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	req.RecursionDesired = false

	mw := mock.NewWriter("udp", "127.0.0.1:0")
	ch.Writer = mw
	ch.Request = req

	ch.Reset(mw, req)
	ch.Next(ctx)

	assert.Equal(t, dns.RcodeServerFailure, mw.Rcode())

	req.RecursionDesired = true

	ch.Reset(mw, req)
	ch.Next(ctx)

	assert.Equal(t, dns.RcodeSuccess, mw.Rcode())

	f.servers = []string{}

	ch.Reset(mw, req)
	ch.Next(ctx)

	assert.Equal(t, dns.RcodeServerFailure, mw.Rcode())

	f.servers = []string{"127.0.0.1:0"}

	ch.Reset(mw, req)
	ch.Next(ctx)

	assert.Equal(t, dns.RcodeServerFailure, mw.Rcode())
}
