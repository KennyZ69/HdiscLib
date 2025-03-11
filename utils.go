package hdisc

import (
	"errors"
	"net"
)

var (
	NoValidInterface = errors.New("No valid net interface found\n")
	ErrorLocalMac    = errors.New("could not retrieve local mac\n")
)

// Returns the local network interface
func LocalIface() (*net.Interface, error) {
	ifis, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, ifi := range ifis {
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 {
			continue
		}

		return &ifi, nil
	}

	return nil, NoValidInterface
}

func ownMac() (net.HardwareAddr, error) {
	ifi, err := LocalIface()
	if err != nil {
		return nil, ErrorLocalMac
	}

	return ifi.HardwareAddr, nil
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
