package main


import (
	"log"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	path := "xdp_tcp_count.o"

	// Subscribe to signals for terminating the program.
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	coll, err := ebpf.LoadCollection(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Can't load %s: %v\n", path, err)
		os.Exit(42)
	}
	fmt.Println(coll)
}
