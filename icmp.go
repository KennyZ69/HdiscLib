package hdisc

import (
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// Returns an array of active IP addresses on the local network
func DiscoverHosts(localIP net.IP, cidr *net.IPNet) ([]net.IP, error) {
	ips, err := GenerateIPsFromNet(localIP, cidr)
	if err != nil {
		return nil, err
	}
	fmt.Println("IPs", ips)

	var wg sync.WaitGroup
	activeChan := make(chan net.IP, len(ips))

	for _, ip := range ips {
		wg.Add(1)
		go func(target net.IP) {
			defer wg.Done()
			Ping(target, &wg, activeChan)
		}(ip)
	}

	wg.Wait()
	close(activeChan)

	var activeHosts []net.IP
	for ip := range activeChan {
		activeHosts = append(activeHosts, ip)
	}

	return activeHosts, nil
}

// Returns the local IP and CIDR (IPNet) alongside with possible error
func GetLocalNet() (net.IP, *net.IPNet, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, nil, err
	}

	for _, ifi := range ifs {
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			localIP, ipNet, err := net.ParseCIDR(addr.String())
			if err != nil || localIP.To4() == nil {
				continue
			}

			return localIP, ipNet, nil
		}
	}

	return nil, nil, fmt.Errorf("No active network could be accessed\n")
}

// Ping given IP address and if active, pass it to the active channel and return bool if active or not
func Ping(ip net.IP, wg *sync.WaitGroup, activeChan chan net.IP) (bool, error) {

	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return false, err
	}
	defer conn.Close()

	pid := os.Getpid() & 0xffff

	echo := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   pid,
			Seq:  1,
			Data: []byte("Ping!"),
		},
	}

	b, err := echo.Marshal(nil)
	if err != nil {
		return false, err
	}

	_, err = conn.WriteTo(b, &net.IPAddr{IP: ip})
	if err != nil {
		return false, err
	}

	buf := make([]byte, 1500)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))

	n, peer, err := conn.ReadFrom(buf)
	if err != nil {
		return false, err
	}

	resp, err := icmp.ParseMessage(1, buf[:n])
	if err != nil {
		return false, err
	}

	if echoReply, ok := resp.Body.(*icmp.Echo); ok {
		if resp.Type == ipv4.ICMPTypeEchoReply && echoReply.ID == pid && peer.String() == ip.String() {
			log.Println("Found active host:", ip.String())
			activeChan <- ip
		}
	}

	return false, nil
}

// Generates all local IP addresses as an array of net.IP without the gateway (first one) and the broadcast (last one)
func GenerateIPsFromNet(localIP net.IP, cidr *net.IPNet) ([]net.IP, error) {
	var ips []net.IP
	firstIP := cidr.IP.Mask(cidr.Mask)

	// increment the first IP to get the first usable host
	incIP(firstIP)

	for ip := firstIP; cidr.Contains(ip); incIP(ip) {
		ipCopy := make(net.IP, len(ip))
		copy(ipCopy, ip)
		ips = append(ips, ipCopy)
	}

	// remove the broadcast address
	if len(ips) > 0 {
		ips = ips[:len(ips)-1]
	}

	return ips, nil
}
