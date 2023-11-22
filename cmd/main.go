package main

import (
	"log"

	"github.com/berylyvos/gosocks5"
)

func main() {
	server := gosocks5.S5Server{
		IP:   "localhost",
		Port: 1080,
	}

	if err := server.Run(); err != nil {
		log.Fatal(err)
	}
}
