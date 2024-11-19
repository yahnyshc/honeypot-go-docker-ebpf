package intercept

import (
	"os"
	"os/signal"
	"time"
	"log"
	"net"
	"C"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"honeypot-go-docker-ebpf/internal/models"
	"honeypot-go-docker-ebpf/internal/ip"
	"honeypot-go-docker-ebpf/build"
)

func AttachInterceptor(ifname string){
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock: ", err)
	}

	var objs build.Packet_inspector_kernObjects
	if err := build.LoadPacket_inspector_kernObjects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects: ", err)
	}
	defer objs.Close()

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

	monitor(objs)
}

func monitor(objs build.Packet_inspector_kernObjects){
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
		  var packet models.Packet_info
		  err := objs.PacketMap.Lookup(uint32(i), &packet)
		  if err == nil {
			log.Printf("Received packet: src: %s:%d, dst: %s:%d, len: %d",
				ip.IntToIP(packet.Src_ip), packet.Src_port,
				ip.IntToIP(packet.Dst_ip), packet.Dst_port,
			  packet.Length,
			)
		  }
		}
		time.Sleep(100 * time.Millisecond) // Avoid busy-waiting
	  }
	}
}