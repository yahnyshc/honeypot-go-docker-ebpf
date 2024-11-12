package main

import (
	"log"
	"net"
	"os"
	"os/signal"
	"time"
	"C"
	"encoding/binary"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

type packet_info struct {
	Src_ip uint32 `bpf:"src_ip"`
	Dst_ip uint32 `bpf:"dst_ip"`
	Src_port uint16 `bpf:"src_port"`
	Dst_port uint16 `bpf:"dst_port"`
	Length uint16 `bpf:"length"`
	_      uint16 // Padding to match the alignment of the C struct
}

func intToIP(ipInt uint32) string {
	// // Convert the integer from network byte order to host byte order
	// ipInt = binary.BigEndian.Uint32([]byte{
	// 	byte(ipInt >> 24),
	// 	byte(ipInt >> 16),
	// 	byte(ipInt >> 8),
	// 	byte(ipInt),
	// })
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, ipInt)
	return ip.String()
}

func main(){
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock: ", err)
	}

	var objs packet_inspector_kernObjects
	if err := loadPacket_inspector_kernObjects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects: ", err)
	}
	defer objs.Close()

	ifname := "ens32"
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		log.Fatalf("Getting interface %s: %s", ifname, err)
	}

	// Attach pakcet inspector kern to network interface
	link, err := link.AttachXDP(link.XDPOptions{
		Program: objs.XdpPacketInspector,
		Interface: iface.Index,
	}); if err != nil {
		log.Fatal("Attach XDP: ", err)
	}
	defer link.Close()

	log.Printf("Intercepting incoming packets on %s...", ifname)

	// Poll for packets continuously
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)
	for {
	  select {
	  case <-stop:
		log.Printf("Received signal, exiting..")
		return
	  default:
		// Attempt to read packets from the map
		for i := 0; i < 1024; i++ {
		  var packet packet_info
		  err := objs.PacketMap.Lookup(uint32(i), &packet)
		  if err == nil {
			log.Printf("Received packet: src: %s:%d, dst: %s:%d, len: %d",
			  intToIP(packet.Src_ip), packet.Src_port,
			  intToIP(packet.Dst_ip), packet.Dst_port,
			  packet.Length,
			)
		  }
		}
		time.Sleep(100 * time.Millisecond) // Avoid busy-waiting
	  }
	}
}