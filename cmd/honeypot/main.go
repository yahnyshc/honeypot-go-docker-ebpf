package main

import (
	"log"
	"C"
	
	"honeypot-go-docker-ebpf/internal/intercept"
)

func main(){
	ifname := "ens32"
	log.Printf("Intercepting incoming packets on %s...", ifname)

	intercept.AttachInterceptor(ifname)
}