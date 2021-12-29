//go:build linux
// +build linux

package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/vishvananda/netlink"
)

var ifname string

func init() {
	flag.StringVar(&ifname, "ifname", "eth1", "interface name")
}

func GetLinkIndexByName(ifname string) int {
	l, _ := netlink.LinkByName(ifname)
	return l.Attrs().Index
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
		Interface: GetLinkIndexByName(ifname),
		Flags:     link.XDPGenericMode,
	})
	if err != nil {
		log.Fatalf("attach xdp error: %s", err)
	}
	defer l.Close()

	var key uint32 = 30001
	val := BackendServer{
		Addr: IP2Uint32("10.41.1.140"),
		Port: 30001,
	}

	err = objs.ProxyMap.Put(&key, &val)
	if err != nil {
		log.Fatalf("set proxy_map error: %s", err)
	}

	<-stopper
}
