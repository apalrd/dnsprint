package dnsprint

import (
    "log"
    "net"
	"strconv"
	"strings"
    "github.com/miekg/dns"
)

type Server struct {
    config *config.Config
    resolver *resolver.Resolver
    translator *translator.Translator
}

func New(cfg *config.Config,res *resolver.Resolver,xlate *translator.Translator) *Server {
    return &Server{config: cfg, resolver: res, translator: xlate}
}

func (s *Server) handleRequest(w dns.ResponseWriter, req *dns.Msg) {
    //vars we will need async
	var (
		aaaaResp *dns.Msg
		aaaaErr  error
		doneCh   chan struct{}
	)

    //orignal question is A?
	q := req.Question[0]
	isA := q.Qtype == dns.TypeA

	// If A request → kick off AAAA asynchronously
	if isA {
		doneCh = make(chan struct{})
		go func() {
			defer close(doneCh)

			aaaaReq := new(dns.Msg)
			aaaaReq.SetQuestion(q.Name, dns.TypeAAAA)

			aaaaResp, aaaaErr = s.resolver.Forward(aaaaReq)
		}()
	}

	//If the request is reverse DNS (in-addr.arpa)
	//and request IP is within the legacy mapping range
	if q.Qtype == dns.TypePTR {
		if ip:= ptrNameToIP(q.Name); ip != nil && s.config.Pool.Contains(ip) {
			//translate this to IPv6
        	ipv6, v6err := s.translator.LookupReverse(ip)
			if ipv6 == nil || v6err != nil {
				//No mapping, return NXDOMAIN		
				if s.config.Debug {
					log.Printf("Synyh PTR Failed: [%s] → NXDOMAIN", q.Name)
				}

				m := new(dns.Msg)
				m.SetRcode(req, dns.RcodeNameError)
				_ = w.WriteMsg(m)
				return
			}

			//Now reverse that address into an ipv6 query
			ip6Arpa, arpaErr := dns.ReverseAddr(ipv6.String())
			if arpaErr != nil {
				//idfk what happened here, return server failure		
				if s.config.Debug {
					log.Printf("Synyh PTR Failed: [%s] → SERVFAIL (%v) (reverse addr synth)", q.Name,arpaErr)
				}

				m := new(dns.Msg)
				m.SetRcode(req, dns.RcodeServerFailure)
				_ = w.WriteMsg(m)
				return
			}

			//Perform PTR query to rdns from the AAAA
			synthReq := new(dns.Msg)
			synthReq.SetQuestion(ip6Arpa, dns.TypePTR)
			synthResp, synthErr := s.resolver.Forward(synthReq)


			//If we died from an error, return servfail 
			if synthErr != nil {
				//idfk what happened here, return server failure		
				if s.config.Debug {
					log.Printf("Synyh PTR Failed: [%s] → SERVFAIL (%v) (failed upstream)", q.Name,synthErr)
				}

				m := new(dns.Msg)
				m.SetRcode(req, dns.RcodeServerFailure)
				_ = w.WriteMsg(m)
				return
			}

			//Got a response from the synth rdns query
			if synthResp != nil && len(synthResp.Answer) > 0 {
				//Generate a new response to the original query
				msg := new(dns.Msg)
				msg.SetReply(req)
				for _, rr := range synthResp.Answer {
					if ptr, ok := rr.(*dns.PTR); ok {
						msg.Answer = append(msg.Answer, &dns.PTR{
							Hdr: dns.RR_Header{
								Name:   q.Name, // use original name, not new name
								Rrtype: dns.TypePTR,
								Class:  dns.ClassINET,
								Ttl:    ptr.Hdr.Ttl,
							},
							Ptr: ptr.Ptr,
						})
					}
				}
				if s.config.Debug {
					log.Printf("Synth PTR: [%s] → %d answers", q.Name, len(msg.Answer))
				}
				_ = w.WriteMsg(msg)
				return
			} 
			
			//general error, return nxdomain	
			if s.config.Debug {
				log.Printf("Synyh PTR Failed: [%s] → NXDOMAIN (query was questionable)", q.Name)
			}

			m := new(dns.Msg)
			m.SetRcode(req, dns.RcodeNameError)
			_ = w.WriteMsg(m)
			return

		}
	}

    //Forward the original request upstream
    resp, err := s.resolver.Forward(req)

	// wait for AAAA if we launched it
	if isA && doneCh != nil {
		<-doneCh
	}

	// check if response failed (no answers or error)
	aFailed := err != nil || resp == nil || len(resp.Answer) == 0
    aaaaFailed := isA && aaaaErr != nil || aaaaResp == nil || len(aaaaResp.Answer) == 0

	// convert query type to a string for later
	qTypeStr := strconv.Itoa(int(q.Qtype))
	switch q.Qtype {
	case dns.TypeA: 
		qTypeStr = "A"
	case dns.TypeAAAA:
		qTypeStr = "AAAA"
	case dns.TypeCNAME:
		qTypeStr = "CNAME"
	case dns.TypeNS:
		qTypeStr = "NS"
	case dns.TypeSRV:
		qTypeStr = "SRV"
	case dns.TypePTR:
		qTypeStr = "PTR"
	}

    // get the ipv6 response (first one, if there are multiple)
	var ipv6 net.IP
    if(!aaaaFailed) {
        for _, ans := range aaaaResp.Answer {
            if aaaa, ok := ans.(*dns.AAAA); ok {
                ipv6 = aaaa.AAAA
                break
            }
		}
    }


    //If original type was A and AAAA succeeded (do synthesis)
	if isA && ipv6 != nil && (aFailed || s.config.PreferSynth) {

        //ask the translator to translate this v6 address
		ipv4, ipv4err := s.translator.Lookup(ipv6)
		if ipv4err == nil && ipv4 != nil {
            //translator did not return an error
			if s.config.Debug {
				log.Printf("Synthesized: [%s] from %s → %s", q.Name, ipv6.String(),ipv4.String())
			}

            //return synthesized A result
			msg := new(dns.Msg)
			msg.SetReply(req)

			a := &dns.A{
				Hdr: dns.RR_Header{
					Name:   q.Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    60,
				},
				A: ipv4,
			}

			msg.Answer = []dns.RR{a}
			_ = w.WriteMsg(msg)
			return
		}
    }

    // If original query failed
	if err != nil || resp == nil {
		if s.config.Debug {
			log.Printf("Query failed: [%s] (%s) → SERVFAIL", q.Name, qTypeStr)
		}

		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeServerFailure)
		_ = w.WriteMsg(m)
		return
	}

    // Else, return the query we got 	
    if s.config.Debug {
		log.Printf("Query passed: [%s] (%s) → %d answers", q.Name, qTypeStr, len(resp.Answer))
	}

	_ = w.WriteMsg(resp)
}

func (s *Server) ListenAndServe() error {
    mux := dns.NewServeMux()
    mux.HandleFunc(".", s.handleRequest)

    server := &dns.Server{
        Addr:    s.config.Listen,
        Net:     "udp",
        Handler: mux,
    }

    log.Printf("DNS server listening on %s", s.config.Listen)
    return server.ListenAndServe()
}

// ptrNameToIP parses an in-addr.arpa. name into a net.IP.
// e.g. "1.2.0.192.in-addr.arpa." → 192.0.2.1
// Returns nil if the name is not a valid IPv4 reverse DNS name.
func ptrNameToIP(name string) net.IP {
    const suffix = ".in-addr.arpa."
    if !strings.HasSuffix(name, suffix) {
        return nil
    }
    // strip suffix, split the reversed octets
    trimmed := strings.TrimSuffix(name, suffix)
    parts := strings.Split(trimmed, ".")
    if len(parts) != 4 {
        return nil
    }
    // reverse the labels to get the correct octet order
    octets := make([]string, 4)
    for i, p := range parts {
        octets[3-i] = p
    }
    ip := net.ParseIP(strings.Join(octets, "."))
    if ip == nil {
        return nil
    }
    return ip.To4()
}