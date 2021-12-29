//go:build linux
// +build linux

package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"
	"flag"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/vishvananda/netlink"
)

var ifIndex int

func init(){
	flag.Int("if")
}

func GetLinkIndexByName(name string) int {
	link,err:=netlink.LinkByName(name)
}

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf xdp_proxy.c -- -I../headers -I/usr/include/x86_64-linux-gnu

func main() {
	// Subscribe to signals for terminating the program.
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpProg,
		Interface: 2,
		Flags:     link.XDPGenericMode,
	})
	if err != nil {
		log.Fatalf("attach xdp error: %s", err)
	}
	defer l.Close()

	key := BackendServer{
		Addr: IP2Uint32("172.16.128.2"),
		Port: 8080,
	}
	val := BackendServer{
		Addr: IP2Uint32("10.41.1.140"),
		Port: 8080,
	}

	err = objs.ProxyMap.Put(&key, &val)
	if err != nil {
		log.Fatalf("set proxy_map error: %s", err)
	}

	<-stopper
}

