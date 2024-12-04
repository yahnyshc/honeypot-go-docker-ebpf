package intercept

import (
  "log"
  "net"

  "github.com/cilium/ebpf/link"
  "github.com/cilium/ebpf/rlimit"
  "honeypot-go-docker-ebpf/build"
)

// AttachInterceptor attaches the eBPF program and returns the loaded objects
// and a cleanup function to release resources.
func AttachInterceptor(ifname string) (*build.Packet_inspector_kernObjects, func()) {
  // Remove the memory lock limit for eBPF
  if err := rlimit.RemoveMemlock(); err != nil {
    log.Fatal("Removing memlock: ", err)
  }

  // Load eBPF objects
  var objs build.Packet_inspector_kernObjects
  if err := build.LoadPacket_inspector_kernObjects(&objs, nil); err != nil {
    log.Fatal("Loading eBPF objects: ", err)
  }

  // Retrieve the network interface
  iface, err := net.InterfaceByName(ifname)
  if err != nil {
    log.Fatalf("Getting interface %s: %s", ifname, err)
  }

  // Attach the XDP program to the interface
  xdpLink, err := link.AttachXDP(link.XDPOptions{
    Program:   objs.XdpPacketInspector,
    Interface: iface.Index,
  })
  if err != nil {
    objs.Close() // Cleanup objects if link creation fails
    log.Fatal("Attach XDP: ", err)
  }

  // Define the cleanup function
  cleanup := func() {
    log.Println("Cleaning up resources...")
    xdpLink.Close() // Close the link
    objs.Close()    // Close eBPF objects
  }

  return &objs, cleanup
}