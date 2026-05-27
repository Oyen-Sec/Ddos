package main

import (
	"log"
	"runtime/debug"

	"ddos-go-engine/internal/attack"
)

func main() {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("FATAL panic: %v\n%s", r, debug.Stack())
		}
	}()

	attack.Main()
}
