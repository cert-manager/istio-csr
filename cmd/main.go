package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"k8s.io/klog/v2"

	"github.com/cert-manager/istio-csr/cmd/app"
)

func main() {
	ctx := signalHandler()
	cmd := app.NewCommand(ctx)

	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func signalHandler() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	ch := make(chan os.Signal, 2)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-ch

		cancel()

		for i := 0; i < 3; i++ {
			klog.Warningf("received signal %s, shutting down gracefully...", sig)
			sig = <-ch
		}

		klog.Errorf("received signal %s, force closing", sig)

		os.Exit(1)
	}()

	return ctx
}
