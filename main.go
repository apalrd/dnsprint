package main

import (
    "os"
    "fmt"
    "net"
    "log"
    "flag"
	"strconv"
    "strings"
    "time"
    "math/rand"
    "gopkg.in/yaml.v3"
    "github.com/miekg/dns"
)

//configuration structure
type Config struct {
    Listen    	string   `yaml:"listen"`     // clients connect to us e.g. "[::]:53"
    GeoDb       string   `yaml:"geodb"`      // path to geo-ip database (.mmdb)
    Domain      string   `yaml:"domain"`     // domain name we respond to (we REFUSE everything else)
    PoolStr     string   `yaml:"pool"`       // address pool for serving http data (cidr-notation)
    PoolIP      *net.IPNet                   // decoded from pool
}

var cfg Config

//load config
func loadConfig(path string) (error) {
    f, err := os.Open(path)
    if err != nil {
        return err
    }
    defer f.Close()

    if err := yaml.NewDecoder(f).Decode(&cfg); err != nil {
        return err
    }

    //validate ip net
    ip, network, err := net.ParseCIDR(cfg.PoolStr)
    if err != nil {
        return fmt.Errorf("invalid CIDR: %w", err)
    }
    if ip.Equal(network.IP) == false {
        return fmt.Errorf("CIDR must be a network address, not a host address")
    }
    mask, total := network.Mask.Size()
    if (total - mask) < 32 {
        return fmt.Errorf("CIDR must have at least 32 bits to work with (mask %d total %d)",mask,total)
    }
    cfg.PoolIP = network

    //validate listen
    if cfg.Listen == "" {
        log.Printf("Listen not specified, using default")
        cfg.Listen = "[::]:53"
    }

    //validate domain is fully qualified
    if !strings.HasSuffix(cfg.Domain,".") {
        return fmt.Errorf("Domain not specified or not fully-qualified (must end with .)")
    }

    return nil
}

// database structure
type DbEntry struct {
    //data related to DNS query
    dnsTime     time.Time
    dnsSrc      net.Addr
    dnsECS      net.IP
    //data related to HTTP queries
    queriedAt   time.Time
}

// database itself
var db map[uint32]DbEntry


//handle a DNS request
func handleDNSRequest(w dns.ResponseWriter, req *dns.Msg) {

    //convert qtype into string for logging later
	q := req.Question[0]
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

    //validate that query is for our domain (DNS will randomize case)
    if !strings.EqualFold(q.Name,cfg.Domain) {
        log.Printf("Got query of invalid name: [%s] %s",qTypeStr,q.Name)
        m := new(dns.Msg)
        m.SetRcode(req, dns.RcodeRefused)
        _ = w.WriteMsg(m)
        return
    }

    //check if question is not an AAAA -> return NOERROR / NOANSWER
    if q.Qtype != dns.TypeAAAA {
        log.Printf("Got query of incorrect type: [%s] %s",qTypeStr,q.Name)
        m := new(dns.Msg)
        m.SetRcode(req, dns.RcodeSuccess)
        _ = w.WriteMsg(m)
        return
    }

    id := rand.Uint32()
    var entry DbEntry

    log.Printf("Got query of correct type: [%s] uid %d",qTypeStr,id)
    entry.dnsTime = time.Now()

    // RemoteAddr() is available directly on ResponseWriter
    remoteAddr := w.RemoteAddr()
    
    // Extract just the IP (strips the port)
    clientIP, _, err := net.SplitHostPort(remoteAddr.String())
    if err != nil {
        // RemoteAddr had no port (unlikely but safe to handle)
        clientIP = remoteAddr.String()
    }
    entry.dnsSrc = remoteAddr
    
    log.Printf("Query from IP: %s", clientIP)

    // get edns client subnet
    if subnet := getECS(req); subnet != nil {
        log.Printf("ECS Address:        %s", subnet.Address)
        log.Printf("ECS Source prefix:  %d", subnet.SourceNetmask)
        log.Printf("ECS Scope prefix:   %d", subnet.SourceScope)
        log.Printf("ECS Family:         %d (1=IPv4, 2=IPv6)", subnet.Family)
        entry.dnsECS = subnet.Address
    } else {
        log.Println("No EDNS Client Subnet in query")
    }

    //store data in db
    db[id] = entry

    log.Printf("DB now has %d entries",len(db))

    m := new(dns.Msg)
    m.SetRcode(req, dns.RcodeSuccess)
	_ = w.WriteMsg(m)
}

//parse opt for edns client subnet
func getECS(r *dns.Msg) *dns.EDNS0_SUBNET {
    opt := r.IsEdns0()
    if opt == nil {
        return nil // No OPT record at all
    }

    for _, option := range opt.Option {
        if subnet, ok := option.(*dns.EDNS0_SUBNET); ok {
            return subnet
        }
    }
    return nil
}

//listen and serve DNS
func listenAndServeDNS() error {
    mux := dns.NewServeMux()
    mux.HandleFunc(".", handleDNSRequest)

    server := &dns.Server{
        Addr:    cfg.Listen,
        Net:     "udp",
        Handler: mux,
    }

    log.Printf("DNS server listening on %s", cfg.Listen)
    return server.ListenAndServe()
}


//main function
func main() {
    configPath := flag.String("conf", "dnsprint.yaml", "path to config file")
    flag.Parse()

    err := loadConfig(*configPath)
    if err != nil {
        log.Fatalf("failed to load config: %v", err)
    }


    //run the server
    if err := listenAndServeDNS(); err != nil {
        log.Fatalf("server error: %v", err)
    }
}