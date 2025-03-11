package main

import (
	"log"
	"os"

	hostdisclibk "github.com/KennyZ69/HdiscLib"
)

func main() {
	if os.Geteuid() != 0 {
		log.Fatalln("You must run this code as root.\n")
	}

	devs, err := hostdisclibk.ARPScan()
	if err != nil {
		log.Fatalf("Error running the arp scan: %s\n", err)
	}

	log.Println("devs:", devs)
}
