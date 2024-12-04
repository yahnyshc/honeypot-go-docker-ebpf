package main

import (
	"log"
	"C"
	"honeypot-go-docker-ebpf/internal/intercept"
	"honeypot-go-docker-ebpf/internal/dockerd"
)

func main(){
	ifname := "lo"
	log.Printf("Intercepting incoming packets on %s...", ifname)

	// Attach interceptor and get the cleanup function
	objs, cleanupEBPF := intercept.AttachInterceptor(ifname)
	defer cleanupEBPF() // Ensure cleanup is called on exit

	dockerd.Monitor(objs)
	defer dockerd.Cleanup()
}