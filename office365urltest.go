package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/brotherpowers/ipsubnet"
)

const (
	dnsserver = "1.1.1.1"
	clientid  = "b10c5ed1-bad1-445f-b386-b919946339a7" // request id from microsoft!
	testvar   = "hoi-test2"
)

type service struct {
	Id                     int      `json:"id"`
	ServiceArea            string   `json:"serviceArea"`
	ServiceAreaDisplayName string   `json:"serviceAreaDisplayName"`
	Urls                   []string `json:"urls"`
	Ips                    []string `json:"ips"`
	TcpPorts               string   `json:"tcpPorts"`
	ExpressRoute           string   `json:"expressRoute"`
	Category               string   `json:"category"`
	Required               bool     `json:"required"`
	Notes                  string   `json:"notes"`
}

type msUrl struct {
	Name        string
	Description string
}

func main() {
	var urls []msUrl

	getMicrosoft(&urls)

	fmt.Printf("\nStarting connectivity tests...\n")
	fmt.Printf("-------------------------------------------------------------------\n\n")

	port := 443
	timeoutArg := 300
	periodArg := 400

	var times uint64 = 20
	var seqNumber uint64 //= 1
	var timeout = time.Duration(timeoutArg) * time.Millisecond
	var period = time.Duration(periodArg) * time.Millisecond

	ticker := time.NewTicker(period)
	quit := make(chan interface{})

	for _, url := range urls {
		var network = fmt.Sprintf("%s:%d", url.Name, port)
		Lookup(url.Name, dnsserver)
		fmt.Printf("-- %s -----------------------------------------------------------------\n", network)
		for seqNumber = 1; seqNumber < times+1; seqNumber++ {
			select {
			case <-ticker.C:
				tryPort(network, seqNumber, timeout)
			case <-quit:
				ticker.Stop()
				return
			}
		}
		fmt.Printf("\n")
	}
}

func tryPort(network string, seq uint64, timeout time.Duration) {
	startTime := time.Now()
	conn, err := net.DialTimeout("tcp", network, timeout)
	endTime := time.Now()
	if err != nil {
		os.Stdout.Write([]byte(startTime.Format("[2006-01-02 15:04:05]") + " connection failed\n"))
	} else {
		defer conn.Close()
		var t = float64(endTime.Sub(startTime)) / float64(time.Millisecond)
		os.Stdout.Write([]byte(startTime.Format("[2006-01-02 15:04:05]") + fmt.Sprintf(" %-20s %-5d %4.2fms %s\n", conn.RemoteAddr().String(), seq, t, reverseLookupServer(conn, dnsserver))))
	}
}

func Lookup(network string, dnsserver string) {

	var resolver *net.Resolver
	resolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{}
			return d.DialContext(ctx, "udp", net.JoinHostPort(dnsserver, "53"))
		},
	}

	addr, err := resolver.LookupCNAME(context.Background(), network)
	if err != nil {
		fmt.Println("Error: ", addr, err)
	}
	fmt.Println("resolved: ", addr)
}

func reverseLookup(conn net.Conn) string {
	ip, _ := splitAddr(conn.RemoteAddr().String())
	addr, err := net.LookupAddr(ip)
	if err != nil {
		//fmt.Println(addr, err)
	}
	if len(addr) == 0 {
		return "-"
	}
	return addr[0]
}

func reverseLookupServer(conn net.Conn, dnsserver string) string {

	ip, _ := splitAddr(conn.RemoteAddr().String())

	var resolver *net.Resolver
	resolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{}
			return d.DialContext(ctx, "udp", net.JoinHostPort(dnsserver, "53"))
		},
	}

	// resolver = net.DefaultResolver (else)
	addr, err := resolver.LookupAddr(context.Background(), ip)

	if err != nil {
		//       fmt.Println("Error: ", addr, err)
	}
	if len(addr) == 0 {
		return "-"
	}
	return addr[0]
}

func splitAddr(conn string) (string, string) {
	s := strings.Split(conn, ":")
	ip, port := s[0], s[1]
	return ip, port
}

var privateRanges = []ipRange{
	ipRange{
		start: net.ParseIP("10.0.0.0"),
		end:   net.ParseIP("10.255.255.255"),
	},
	ipRange{
		start: net.ParseIP("100.64.0.0"),
		end:   net.ParseIP("100.127.255.255"),
	},
	ipRange{
		start: net.ParseIP("172.16.0.0"),
		end:   net.ParseIP("172.31.255.255"),
	},
	ipRange{
		start: net.ParseIP("192.0.0.0"),
		end:   net.ParseIP("192.0.0.255"),
	},
	ipRange{
		start: net.ParseIP("192.168.0.0"),
		end:   net.ParseIP("192.168.255.255"),
	},
	ipRange{
		start: net.ParseIP("198.18.0.0"),
		end:   net.ParseIP("198.19.255.255"),
	},
}

type ipRange struct {
	start net.IP
	end   net.IP
}

// inRange - check to see if a given ip address is within a range given
func inRange(r ipRange, ipAddress net.IP) bool {
	// strcmp type byte comparison
	if bytes.Compare(ipAddress, r.start) >= 0 && bytes.Compare(ipAddress, r.end) < 0 {
		return true
	}
	return false
}

// isPrivateSubnet - check to see if this ip is in a private subnet
func isPrivateSubnet(ipAddress net.IP) bool {
	// my use case is only concerned with ipv4 atm
	if ipCheck := ipAddress.To4(); ipCheck != nil {
		// iterate over all our ranges
		for _, r := range privateRanges {
			// check if this ip is in a private range
			if inRange(r, ipAddress) {
				return true
			}
		}
	}
	return false
}

func getMicrosoft(urls *[]msUrl) {
	response, err := http.Get(fmt.Sprintf("https://endpoints.office.com/endpoints/worldwide?clientrequestid=%s", clientid))

	if err != nil {
		fmt.Sprintf("Could not get office365 url's: %s\n", err)
	} else {
		data, _ := ioutil.ReadAll(response.Body)

		var jsonData []service
		json.Unmarshal(data, &jsonData)

		for _, d := range jsonData {
			dummy := ""
			if len(d.Ips) > 0 && d.Category == "Optimize" {
				fmt.Printf("%s - %s\n", d.ServiceArea, d.ServiceAreaDisplayName, d.Category, d.Notes)
				for _, net := range d.Ips {
					if !strings.Contains(net, ":") {
						fmt.Printf("%s &#9670; ", net)
						s := strings.Split(net, "/")
						ip, subnet := s[0], s[1]
						cidr, _ := strconv.Atoi(subnet)

						ports := strings.Split(d.TcpPorts, ",")
						for _, port := range ports {
							sub := ipsubnet.SubnetCalculator("255.255.255.255", cidr)
							dummy = fmt.Sprintf("%s   permit tcp any %s %s eq %s\n", dummy, ip, sub.GetHostPortion(), port)
						}
					}
				}
			}
		}

		for _, d := range jsonData {
			for _, url := range d.Urls {
				fmt.Printf("%-51s %s %s required:%t\n", fmt.Sprintf("%s%s%s", "\"", url, "\""), d.ServiceArea, d.ServiceAreaDisplayName, d.Required)

				var myurl msUrl
				myurl.Name = url
				myurl.Description = d.ServiceAreaDisplayName

				//
				if !strings.Contains(url, "*") && d.Required {
					*urls = append(*urls, myurl)
				}
			}
		}
	}
}
