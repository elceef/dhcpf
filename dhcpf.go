// dhcpf
// (c) Marcin Ulikowski <elceef@gmail.com>

package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
	"os"
	"strings"
	"time"
)

var (
	device      string
	snapshotLen int32 = 1024
	promiscuous bool  = false
	err         error
	timeout     time.Duration = 30 * time.Second
	handle      *pcap.Handle
)

type dhcpFprint struct {
	TTL    uint8
	opts   []uint8
	opt55  []uint8
	vendor string
	osname string
}

type dhcpMsg struct {
	Op     uint8
	Htype  uint8
	Hlen   uint8
	Hops   uint8
	Xid    uint32
	Secs   uint16
	Flags  uint16
	Ciaddr uint32
	Yiaddr uint32
	Siaddr uint32
	Giaddr uint32
	Chaddr [16]byte
	Sname  [64]byte
	File   [128]byte
	Cookie uint32
	//Options uint8
}

var fp []dhcpFprint

func main() {
	fmt.Printf("=== dhcpf: passive DHCP fingerprinting ===\n\n")
	if len(os.Args) < 2 {
		fmt.Printf("Usage: %s <interface/pcap>\n", os.Args[0])
		os.Exit(1)
	}

	loadSignatures()

	if len(fp) > 0 {
		fmt.Printf("Successfully loaded %d DHCP-prints\n\n", len(fp))
	} else {
		fmt.Printf("Warning: No valid fingerprints found!\n\n")
		//os.Exit(1)
	}

	device = os.Args[1]

	handle, err = pcap.OpenLive(device, snapshotLen, promiscuous, timeout)
	if err != nil {
		handle, err = pcap.OpenOffline(device)
	}
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	var filter string = "udp[9] == 1 and src port 68 and dst port 67 and greater 267"
	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatal(err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		parsePacket(packet)
	}
}

func loadSignatures() {
	file, err := os.Open("dhcpf.prints")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		if strings.HasPrefix(scanner.Text(), "!") == false &&
			scanner.Text() != "" {
			s := strings.Split(scanner.Text(), "|")
			var ttl uint8
			fmt.Sscanf(s[0], "%d", &ttl)
			var opts []uint8
			for _, v := range strings.Split(s[1], ",") {
				var x uint8
				fmt.Sscanf(v, "%d", &x)
				opts = append(opts, x)
			}
			var opt55 []uint8
			for _, v := range strings.Split(s[2], ",") {
				var x uint8
				fmt.Sscanf(v, "%d", &x)
				opt55 = append(opt55, x)
			}
			var vendor string
			if s[3] != "(null)" {
				vendor = s[3]
			}
			osname := s[4]

			sig := dhcpFprint{ttl, opts, opt55, vendor, osname}
			fp = append(fp, sig)
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

	//for i := 0; i < len(fp); i++ {
	//	fmt.Println(fp[i])
	//}
}

func roundTTL(ttl uint8) int {
	if ttl <= 32 {
		return 32
	} else if ttl <= 64 && ttl > 32 {
		return 64
	} else if ttl <= 128 && ttl > 64 {
		return 128
	} else if ttl > 128 {
		return 255
	}
	return 0 // shouldn't happen :)
}

func matchSystem(ttl uint8, opts []uint8, opt55 []uint8, vendor string) string {
	for i := 0; i < len(fp); i++ {
		if fp[i].TTL == ttl || fp[i].TTL == 0 {
			if bytes.Equal(fp[i].opts, opts) || fp[i].opts[0] == 0 {
				if bytes.Equal(fp[i].opt55, opt55) || fp[i].opt55[0] == 0 {
					if fp[i].vendor == vendor || fp[i].vendor == "*" {
						return fp[i].osname
					}
				}
			}
		}
	}
	var sopts []string
	for i := 0; i < len(opts); i++ {
		sopts = append(sopts, fmt.Sprintf("%d", opts[i]))
	}
	var sopt55 []string
	for i := 0; i < len(opt55); i++ {
		sopt55 = append(sopt55, fmt.Sprintf("%d", opt55[i]))
	}
	return fmt.Sprintf("%d|%s|%s|%s|UNKNOWN", ttl, strings.Join(sopts, ","), strings.Join(sopt55, ","), vendor)
}

func formatMAC(mac []byte) string {
	var m []string
	for i := 0; i < len(mac); i++ {
		m = append(m, fmt.Sprintf("%x", mac[i]))
	}
	return strings.Join(m, ":")
}

func dhcpType(code int) string {
	switch code {
	case 1: // DISCOVER
		return "DHCP Discover"
	case 3: // REQUEST
		return "DHCP Request"
	case 8: // INFORM
		return "DHCP Inform"
	}
	return "DHCP Unknown"
}

func parsePacket(packet gopacket.Packet) {
	var srcMAC []byte
	ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethernetLayer != nil {
		ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
		srcMAC = ethernetPacket.SrcMAC
	}

	var TTL uint8 = 0
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		TTL = uint8(ip.TTL)
	}

	applicationLayer := packet.ApplicationLayer()
	if applicationLayer != nil {
		var message int
		var vendor string
		var opts []uint8
		var opt55 []uint8
		var dhcpHeader dhcpMsg

		buf := bytes.NewBuffer(applicationLayer.Payload())
		//fmt.Println(buf)
		err = binary.Read(buf, binary.BigEndian, &dhcpHeader)
		if err != nil {
			fmt.Println("binary.Read failed:", err)
		}
		var options []byte = applicationLayer.Payload()[binary.Size(dhcpHeader):]
		//fmt.Println(options)

		for i := 0; i < len(options); i++ {
			opt := int(options[i])
			len := int(options[i+1])

			if opt != 255 && opt != 0 && opt != 82 {
				opts = append(opts, uint8(opt))
			}

			switch opt {
			case 53: // DHCP_MESSAGE_TYPE
				message = int(options[i+1])

			case 55: // DHCP_PARAMETER_REQUEST_LIST
				for j := 0; j < len; j++ {
					opt55 = append(opt55, uint8(options[i+j+2]))
				}

			case 60: // VENDOR_CLASS_IDENTIFIER
				vendor = string(options[i+2 : i+2+len])
			}

			i += len + 1
		}

		//fmt.Println(opts, opt55, vendor)
		log.Printf("%s %s %s\n", dhcpType(message), formatMAC(srcMAC), matchSystem(TTL, opts, opt55, vendor))
	}

	if err := packet.ErrorLayer(); err != nil {
		fmt.Println("Error decoding some part of the packet:", err)
	}
}
