package common

import (
	"fmt"
	"log"

	"github.com/google/gopacket/pcap"
)

func Com_print(a int, b int) int {
	fmt.Printf("a = %d, b = %d\n", a, b)
	return 0
}

func Go_packet() {
	// Find all devices

	devices, err := pcap.FindAllDevs()

	if err != nil {

		log.Fatal(err)

	}

	// Print device information

	fmt.Println("Devices found:")

	for _, device := range devices {

		fmt.Println("\nName: ", device.Name)

		fmt.Println("Description: ", device.Description)

		fmt.Println("Devices addresses: ", device.Description)

		for _, address := range device.Addresses {

			fmt.Println("- IP address: ", address.IP)

			fmt.Println("- Subnet mask: ", address.Netmask)

		}

	}
}
