package main

import (
	"context"
	"github.com/bwmp-dev/provenance/packages/cli-go/internal/command"
	"github.com/bwmp-dev/provenance/packages/cli-go/internal/securestore"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	app := command.App{Out: os.Stdout, Err: os.Stderr, In: os.Stdin, Store: securestore.New()}
	os.Exit(app.Run(ctx, os.Args[1:]))
}
