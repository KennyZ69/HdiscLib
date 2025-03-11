package hdisc

import (
	"bytes"
	"context"
	"log"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	manuf "github.com/timest/gomanuf"
)

// Struct to hold device data
type DevData struct {
	Mac      net.HardwareAddr
	IP       net.IP
	Hostname string
	Manuf    string
}

// Scan the local network for active devices and returns an array of device data with possible error
func ARPScan() ([]DevData, error) {
	log.Println("Starting up the ARP Scan")

	ifi, err := LocalIface()
	if err != nil {
		return nil, err
	}

	handle, err := pcap.OpenLive(ifi.Name, 65536, true, pcap.BlockForever)
	if err != nil {
		return nil, err
	}
	defer handle.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	devsChan := make(chan DevData, 50)
	devices := []DevData{}

	go ListenARP(handle, ifi, ctx, devsChan)

	for {
		if err := SendARP(handle); err != nil {
			log.Printf("error writing arp packets: %s\n", err)
			return nil, err
		}

		// wait for arp responses
		time.Sleep(time.Second * 5)
		ctx.Done()
		close(devsChan)
		for d := range devsChan {
			devices = append(devices, d)
		}
		return devices, nil
	}
}

// Send ARP packets to all the local ip addresses
func SendARP(handle *pcap.Handle) error {
	localIP, ipNet, err := GetLocalNet()
	if err != nil {
		return err
	}

	ips, err := GenerateIPsFromNet(localIP, ipNet)
	if err != nil {
		return err
	}
	for _, ip := range ips {
		if err := SendARPPacket(handle, localIP, ip); err != nil {
			continue
		}
	}

	return nil
}

// Send an ARP packet through the handle
func SendARPPacket(handle *pcap.Handle, srcIP, targetIP net.IP) error {
	localHaddr, err := ownMac()
	if err != nil {
		return err
	}

	eth := &layers.Ethernet{
		SrcMAC:       localHaddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}

	arp := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     uint8(6),
		ProtAddressSize:   uint8(4),
		Operation:         layers.ARPRequest, // 1 as a request and 2 as a reply
		SourceHwAddress:   []byte(localHaddr),
		SourceProtAddress: srcIP.To4(),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    targetIP.To4(),
	}

	buf := gopacket.NewSerializeBuffer()
	opt := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	gopacket.SerializeLayers(buf, opt, eth, arp)

	if err := handle.WritePacketData(buf.Bytes()); err != nil {
		return err
	}

	return nil
}

// listen for arp packets till ctx.done isnt called and pass device data to data channel
func ListenARP(handle *pcap.Handle, ifi *net.Interface, ctx context.Context, dataChan chan DevData) {
	log.Println("Listening for ARP packets")

	ps := gopacket.NewPacketSource(handle, handle.LinkType())
	packs := ps.Packets()
	for {
		select {
		case <-ctx.Done():
			return // just end the listening process
		case p := <-packs:
			arpLayer := p.Layer(layers.LayerTypeARP)
			if arpLayer == nil {
				continue
			}
			arp := arpLayer.(*layers.ARP)

			if arp.Operation != layers.ARPReply || bytes.Equal([]byte(ifi.HardwareAddr), arp.SourceHwAddress) {
				continue // means I probably sent this packet
			}
			// here I am successfully getting an arp reply
			// and I can access its data and somehow send them or print out
			mac := net.HardwareAddr(arp.SourceHwAddress)
			ip := net.IP(arp.SourceProtAddress)
			man := manuf.Search(mac.String())

			data := DevData{Mac: mac, IP: ip, Manuf: man}
			dataChan <- data

			// fmt.Printf("%-15s %-17s %-30s %-10s\n", ip.String(), mac.String(), "", man)

		}
	}
}
