package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/golibs/netutil/sysresolv"
	"github.com/miekg/dns"
)

var VersionString = ""

func main() {
	enableJsonOutput := os.Getenv("JSON") == "1"
	skipTLSCertVerify := os.Getenv("VERIFY") == "0"
	timeoutStr := os.Getenv("TIMEOUT")
	enableHTTP3 := os.Getenv("HTTP3") == "1"
	verbose := os.Getenv("VERBOSE") == "1"
	subnetOpt := getSubnet()
	padding := os.Getenv("PAD") == "1"

	if verbose {
		log.SetLevel(log.DEBUG)
	}

	if !enableJsonOutput {
		_, _ = fmt.Fprintf(os.Stdout, "loo %s\n", VersionString)

		if len(os.Args) == 2 && (os.Args[1] == "-v" || os.Args[1] == "--version") {
			os.Exit(0)
		}
	}

	if skipTLSCertVerify {
		_, _ = os.Stdout.WriteString("TLS verification has been disabled\n")
	}

	if len(os.Args) == 2 && (os.Args[1] == "-h" || os.Args[1] == "--help") {
		usage()
		os.Exit(0)
	}

	if len(os.Args) < 2 || len(os.Args) > 4 {
		log.Printf("Invalid command arguments. Please check the usage below.\n")
		usage()
		os.Exit(0)
	}

	question := getQuestion()

	timeout := 10
	if timeoutStr != "" {
		i, err := strconv.Atoi(timeoutStr)
		if err != nil {
			log.Printf("invalid timeout value: %s", timeoutStr)
			usage()
			os.Exit(0)
		}
		timeout = i
	}

	var server string
	if len(os.Args) > 2 {
		server = os.Args[2]
	} else {
		sysr, err := sysresolv.NewSystemResolvers(nil, 53)
		if err != nil {
			log.Printf("can't get os dns resolvers: %v", err)
			os.Exit(0)
		}
		server = sysr.Addrs()[0].String()
	}

	var httpVersions []upstream.HTTPVersion
	if enableHTTP3 {
		httpVersions = []upstream.HTTPVersion{
			upstream.HTTPVersion3,
			upstream.HTTPVersion2,
			upstream.HTTPVersion11,
		}
	}

	opts := &upstream.Options{
		Timeout:            time.Duration(timeout) * time.Second,
		InsecureSkipVerify: skipTLSCertVerify,
		HTTPVersions:       httpVersions,
	}

	if len(os.Args) == 4 {
		ip := net.ParseIP(os.Args[3])
		if ip == nil {
			log.Fatalf("invalid IP specificed: %s", os.Args[3])
		}
		opts.Bootstrap = &singleIPResolver{ip: ip}
	}

	u, err := upstream.AddressToUpstream(server, opts)
	if err != nil {
		log.Fatalf("can't create upstream: %s", err)
	}

	req := &dns.Msg{}
	req.Id = dns.Id()
	req.RecursionDesired = true
	req.Question = []dns.Question{question}

	if subnetOpt != nil {
		opt := getOrCreateOpt(req)
		opt.Option = append(opt.Option, subnetOpt)
	}

	if padding {
		opt := getOrCreateOpt(req)
		opt.Option = append(opt.Option, newEDNS0Padding(req))
	}

	startTime := time.Now()
	rep, err := u.Exchange(req)
	if err != nil {
		log.Fatalf("can't make the DNS request: %s", err)
	}

	if !enableJsonOutput {
		msg := fmt.Sprintf("dnslookup result (elapsed %v):\n", time.Now().Sub(startTime))
		_, _ = os.Stdout.WriteString(fmt.Sprintf("DNS Server: %s\n\n", server))
		_, _ = os.Stdout.WriteString(msg)
		_, _ = os.Stdout.WriteString(rep.String() + "\n")
	} else {
		// Prevent JSON parsing from skewing results
		endTime := time.Now()

		var JSONreply jsonMsg
		JSONreply.Msg = *rep
		JSONreply.Elapsed = endTime.Sub(startTime)

		var b []byte
		b, err = json.MarshalIndent(JSONreply, "", "  ")
		if err != nil {
			log.Fatalf("Cannot marshal json: %s", err)
		}

		_, _ = os.Stdout.WriteString(string(b) + "\n")
	}

}

func usage() {
	_, _ = os.Stdout.WriteString("Usage: loo <domain> <server> \n")
	_, _ = os.Stdout.WriteString("<domain>: mandatory, domain name to lookup\n")
	_, _ = os.Stdout.WriteString("<server>: mandatory, server address. Supported: plain, tcp:// (TCP), tls:// (DOT), https:// (DOH), sdns:// (DNSCrypt), quic:// (DOQ)\n")
	_, _ = os.Stdout.WriteString("More details, see https://github.com/yonomesh/loo/blob/main/README.md\n")
}

// getQuestion returns a DNS question for the query.
func getQuestion() (q dns.Question) {
	domain := os.Args[1]
	rrType := getRRType()
	qClass := getClass()

	// If the user tries to query an IP address and does not specify any
	// query type, convert to PTR automatically.
	ip := net.ParseIP(domain)
	if os.Getenv("RRTYPE") == "" && ip != nil {
		domain = ipToPtr(ip)
		rrType = dns.TypePTR
	}

	q.Name = dns.Fqdn(domain)
	q.Qtype = rrType
	q.Qclass = qClass

	return q
}

func getRRType() (rrType uint16) {
	rrTypeStr := os.Getenv("RRTYPE")
	var ok bool
	rrType, ok = dns.StringToType[rrTypeStr]
	if !ok {
		if rrTypeStr != "" {
			log.Printf("Invalid RRTYPE: %q", rrTypeStr)
			usage()

			os.Exit(1)
		}

		rrType = dns.TypeA
	}
	return rrType
}

func getClass() (class uint16) {
	classStr := os.Getenv("CLASS")
	var ok bool
	class, ok = dns.StringToClass[classStr]
	if !ok {
		if classStr != "" {
			log.Printf("Invalid CLASS: %q", classStr)
			usage()

			os.Exit(1)
		}

		class = dns.ClassINET
	}
	return class
}

func ipToPtr(ip net.IP) (ptr string) {
	if ip.To4() != nil {
		return ip4ToPtr(ip)
	}

	return ip6ToPtr(ip)
}

func ip4ToPtr(ip net.IP) (ptr string) {
	parts := strings.Split(ip.String(), ".")
	for i := range parts {
		ptr = parts[i] + "." + ptr
	}
	ptr = ptr + "in-addr.arpa."

	return
}

func ip6ToPtr(ip net.IP) (ptr string) {
	addr, _ := netip.ParseAddr(ip.String())
	str := addr.StringExpanded()

	// Remove colons and reverse the order of characters.
	str = strings.ReplaceAll(str, ":", "")
	reversed := ""
	for i := len(str) - 1; i >= 0; i-- {
		reversed += string(str[i])
		if i != 0 {
			reversed += "."
		}
	}

	ptr = reversed + ".ip6.arpa."

	return ptr
}

type singleIPResolver struct {
	ip net.IP
}

var _ upstream.Resolver = (*singleIPResolver)(nil)

func (s *singleIPResolver) LookupNetIP(_ context.Context, _ string, _ string) (addrs []netip.Addr, err error) {
	ip, ok := netip.AddrFromSlice(s.ip)
	if !ok {
		return nil, fmt.Errorf("invalid IP: %s", s.ip)
	}
	return []netip.Addr{ip}, nil
}

func getOrCreateOpt(req *dns.Msg) (opt *dns.OPT) {
	opt = req.IsEdns0()
	if opt == nil {
		req.SetEdns0(udpBufferSize, false)
		opt = req.IsEdns0()
	}

	return opt
}

func getSubnet() (option *dns.EDNS0_SUBNET) {
	subnetStr := os.Getenv("SUBNET")
	if subnetStr == "" {
		return nil
	}

	_, ipNet, err := net.ParseCIDR(subnetStr)
	if err != nil {
		log.Printf("invalid SUBNET: %s", subnetStr)
		os.Exit(0)
	}

	ones, _ := ipNet.Mask.Size()

	return &dns.EDNS0_SUBNET{
		Code:          dns.EDNS0SUBNET,
		Family:        1,
		SourceNetmask: uint8(ones),
		SourceScope:   0,
		Address:       ipNet.IP,
	}
}

// requestPaddingBlockSize is used to pad responses over DoT and DoH according
// to RFC 8467.
const requestPaddingBlockSize = 128
const udpBufferSize = dns.DefaultMsgSize

// newEDNS0Padding constructs a new OPT RR EDNS0 Padding for the extra section.
func newEDNS0Padding(req *dns.Msg) (option *dns.EDNS0_PADDING) {
	msgLen := req.Len()
	padLen := requestPaddingBlockSize - msgLen%requestPaddingBlockSize

	// Truncate padding to fit in UDP buffer.
	if msgLen+padLen > udpBufferSize {
		padLen = udpBufferSize - msgLen
		if padLen < 0 {
			padLen = 0
		}
	}

	return &dns.EDNS0_PADDING{Padding: make([]byte, padLen)}
}

type jsonMsg struct {
	dns.Msg
	Elapsed time.Duration `json:"elapsed"`
}
