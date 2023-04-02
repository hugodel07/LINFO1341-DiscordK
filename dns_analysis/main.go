package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	_ "github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"golang.org/x/exp/slices"
	"os"
	"path/filepath"
	"strings"
)

func getDnsData(filename string) {
	handle, err := pcap.OpenOffline(filename)
	if err != nil {
		panic(err)
	}
	defer handle.Close()

	packets := gopacket.NewPacketSource(handle, handle.LinkType()).Packets()

	//var domainNamesResolved []string
	//var ips []string

	var domainNamesAndIps map[string][]string = make(map[string][]string)

	for pkt := range packets {
		// loop through all layers in the packet to find the dns layer
		dnsLayer := pkt.Layer(layers.LayerTypeDNS)
		if dnsLayer != nil {

			// get the dns layer
			dns, _ := dnsLayer.(*layers.DNS)

			// loop through all questions and answers
			for _, q := range dns.Questions {
				if q.Type == layers.DNSTypeA || q.Type == layers.DNSTypeAAAA {
					//fmt.Printf("DNS %s query for %s\n", q.Type, string(q.Name))

					// if the domain name is not already in the map, add it
					if _, ok := domainNamesAndIps[string(q.Name)]; !ok {
						domainNamesAndIps[string(q.Name)] = []string{}
					}
					//if !slices.Contains(domainNamesResolved, string(q.Name)) {
					//	domainNamesResolved = append(domainNamesResolved, string(q.Name))
					//}
				}
			}

			if dns.AA {
				fmt.Printf("DNS response is authoritative")
			}

			//fmt.Println(dns.Additionals)
			for _, a := range dns.Answers {
				if a.Type == layers.DNSTypeA || a.Type == layers.DNSTypeAAAA {
					//fmt.Printf("DNS %s answer for %s is %s\n", a.Type, string(a.Name), a.IP.String())
					// if the IP is not already in the map, add it
					if !slices.Contains(domainNamesAndIps[string(a.Name)], a.IP.String()) {
						domainNamesAndIps[string(a.Name)] = append(domainNamesAndIps[string(a.Name)], a.IP.String())
					}
					//if !slices.Contains(ips, a.IP.String()) {
					//	ips = append(ips, a.IP.String())
					//}
				}
			}
		}
	}

	//discordDomains := 0
	//for _, domain := range domainNamesResolved {
	//	if strings.Contains(domain, "discord") {
	//		discordDomains++
	//	}
	//}

	fmt.Printf("\nTrace: %s ---------------------------\n", filename)
	fmt.Println("Domain names and IPs found: ", domainNamesAndIps)
	//fmt.Printf("Domain names resolved (%d): %s\n", len(domainNamesResolved), domainNamesResolved)
	//fmt.Printf("IPs found in answers (%d): %s\n", len(ips), ips)
	//fmt.Printf("Discord domains found: %d\n", discordDomains)
}

func getIpData(filename string) {
	handle, err := pcap.OpenOffline(filename)
	if err != nil {
		panic(err)
	}
	defer handle.Close()

	//var ips []string
	var ipsMap map[string]int = make(map[string]int)

	fmt.Printf("\nTrace: %s ---------------------------\n", filename)

	packets := gopacket.NewPacketSource(handle, handle.LinkType()).Packets()

	for pkt := range packets {
		ipv4Layer := pkt.Layer(layers.LayerTypeIPv4)
		if ipv4Layer != nil {

			// get the ip layer
			ip, _ := ipv4Layer.(*layers.IPv4)

			//fmt.Println("IP: ", ip.SrcIP, " -> ", ip.DstIP)
			//if !slices.Contains(ips, ip.SrcIP.String()) {
			//	ips = append(ips, ip.SrcIP.String())
			//}
			//if !slices.Contains(ips, ip.DstIP.String()) {
			//	ips = append(ips, ip.DstIP.String())
			//}

			// add 1 to the count of the ip in the ipsMap
			ipsMap[ip.SrcIP.String()]++
			ipsMap[ip.DstIP.String()]++
		}
	}
	fmt.Println("IPs and their count: ", ipsMap)

	//fmt.Printf("IPs found in answers (%d): %s\n", len(ips), ips)

}

func main() {
	root := "../"
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		// search for all .pcapng and .pcap files
		if !info.IsDir() && (strings.HasSuffix(info.Name(), ".pcapng") || strings.HasSuffix(info.Name(), ".pcap")) {
			//getDnsData(path)
			getIpData(path)
		}
		return nil
	})
	if err != nil {
		fmt.Println(err)
	}
}
