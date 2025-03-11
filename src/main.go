package main

import (
	"log"

	hostdisclibk "github.com/KennyZ69/HdiscLib"
)

func main() {
	localIP, ipNet, err := hostdisclibk.GetLocalNet()
	if err != nil {
		log.Fatalf("Error getting local net: %s\n", err)
	}

	log.Printf("Scanning net: %s\n", ipNet.String())

	activeHosts, err := hostdisclibk.DiscoverHosts(localIP, ipNet)
	if err != nil {
		log.Fatalf("Error getting active hosts: %s\n", err)
	}

	log.Println("Found active hosts:", activeHosts)
}
