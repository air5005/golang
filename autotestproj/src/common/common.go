package common

import (
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	lastTS    time.Time
	lastSend  time.Time
	start     time.Time
	bytesSent int
)

func Com_task() {
	for {
		fmt.Printf("goroutine test \n")
		time.Sleep(time.Duration(1) * time.Second)
	}
}

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

// Convert net.IP to uint32
func Com_inetaton(ipv4 net.IP) (sum uint32) {
	bits := strings.Split(ipv4.String(), ".")

	b0, _ := strconv.Atoi(bits[0])
	b1, _ := strconv.Atoi(bits[1])
	b2, _ := strconv.Atoi(bits[2])
	b3, _ := strconv.Atoi(bits[3])

	sum += uint32(b0) << 24
	sum += uint32(b1) << 16
	sum += uint32(b2) << 8
	sum += uint32(b3)

	return sum
}

func writePacketDelayed(handle *pcap.Handle, buf []byte, ci gopacket.CaptureInfo) {
	if ci.CaptureLength != ci.Length {
		// do not write truncated packets
		return
	}

	intervalInCapture := ci.Timestamp.Sub(lastTS)
	elapsedTime := time.Since(lastSend)

	if (intervalInCapture > elapsedTime) && !lastSend.IsZero() {
		time.Sleep(intervalInCapture - elapsedTime)
	}

	lastSend = time.Now()
	writePacket(handle, buf)
	lastTS = ci.Timestamp
}

func writePacket(handle *pcap.Handle, buf []byte) error {
	if err := handle.WritePacketData(buf); err != nil {
		log.Printf("Failed to send packet: %s\n", err)
		return err
	}
	return nil
}

func pcapInfo(filename string) (start time.Time, end time.Time, packets int, size int) {
	handleRead, err := pcap.OpenOffline(filename)
	if err != nil {
		log.Fatal("PCAP OpenOffline error (handle to read packet):", err)
	}

	var previousTs time.Time
	var deltaTotal time.Duration

	for {
		data, ci, err := handleRead.ReadPacketData()
		if err != nil && err != io.EOF {
			log.Fatal(err)
		} else if err == io.EOF {
			break
		} else {

			if start.IsZero() {
				start = ci.Timestamp
			}
			end = ci.Timestamp
			packets++
			size += len(data)

			if previousTs.IsZero() {
				previousTs = ci.Timestamp
			} else {
				deltaTotal += ci.Timestamp.Sub(previousTs)
				previousTs = ci.Timestamp
			}
		}
	}
	sec := int(deltaTotal.Seconds())
	if sec == 0 {
		sec = 1
	}
	//	fmt.Printf("Avg packet rate %d/s\n", packets/sec)
	return start, end, packets, size
}

func Com_sendpcap(iface string, fname string, fast bool) int {

	// Open PCAP file + handle potential BPF Filter
	handleRead, err := pcap.OpenOffline(fname)
	if err != nil {
		log.Fatal("PCAP OpenOffline error (handle to read packet):", err)
		return -1
	}
	defer handleRead.Close()

	// Open up a second pcap handle for packet writes.
	handleWrite, err := pcap.OpenLive(iface, 65536, true, pcap.BlockForever)
	if err != nil {
		log.Fatal("PCAP OpenLive error (handle to write packet):", err)
		return -1
	}
	defer handleWrite.Close()

	start = time.Now()
	pkt := 0
	tsStart, tsEnd, packets, size := pcapInfo(fname)

	// Loop over packets and write them
	for {
		data, ci, err := handleRead.ReadPacketData()
		switch {
		case err == io.EOF:
			//			fmt.Printf("Finished in %s\n", time.Since(start))
			return 0
		case err != nil:
			log.Printf("Failed to read packet %d: %s\n", pkt, err)
			return -1
		default:
			if fast {
				writePacket(handleWrite, data)
			} else {
				writePacketDelayed(handleWrite, data, ci)
			}

			bytesSent += len(data)
			duration := time.Since(start)
			pkt++

			if duration > time.Second {
				rate := bytesSent / int(duration.Seconds())
				remainingTime := tsEnd.Sub(tsStart) - duration
				//				fmt.Printf("\rrate %d kB/sec - sent %d/%d kB - %d/%d packets - remaining time %s",
				//					rate/1000, bytesSent/1000, size/1000,
				//					pkt, packets, remainingTime)
				rate = rate
				bytesSent = bytesSent
				size = size
				pkt = pkt
				packets = packets
				remainingTime = remainingTime
			}
		}
	}

	return 0
}

func Com_getpcapinfo(fname string) (ret int, SrcIp, DstIp uint32, SrcPort, DstPort uint16, Protocol uint8) {
	ret = -1
	handleRead, err := pcap.OpenOffline(fname)
	if err != nil {
		log.Fatal("PCAP OpenOffline error (handle to read packet):", err)
		return ret, SrcIp, DstIp, SrcPort, DstPort, Protocol
	}
	defer handleRead.Close()

	packetSource := gopacket.NewPacketSource(handleRead, handleRead.LinkType())

	for packet := range packetSource.Packets() {
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer != nil {
			ip, _ := ipLayer.(*layers.IPv4)
			SrcIp = Com_inetaton(ip.SrcIP)
			DstIp = Com_inetaton(ip.DstIP)
			Protocol = (uint8)(ip.Protocol)

			if Protocol == 6 {
				tcpLayer := packet.Layer(layers.LayerTypeTCP)

				if tcpLayer != nil {
					tcp, _ := tcpLayer.(*layers.TCP)
					SrcPort = (uint16)(tcp.SrcPort)
					DstPort = (uint16)(tcp.DstPort)
				}
			} else if Protocol == 17 {
				udpLayer := packet.Layer(layers.LayerTypeUDP)

				if udpLayer != nil {
					udp, _ := udpLayer.(*layers.UDP)
					SrcPort = (uint16)(udp.SrcPort)
					DstPort = (uint16)(udp.DstPort)
				}
			}
		}
		return 0, SrcIp, DstIp, SrcPort, DstPort, Protocol
	}
	return ret, SrcIp, DstIp, SrcPort, DstPort, Protocol
}
