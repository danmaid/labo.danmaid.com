package main

import (
	"log"
)

func main() {

	cfg, err := LoadConfig(
		"./examples/config.yaml",
	)
	if err != nil {
		log.Fatal(err)
	}

	rt, err := NewRuntime(cfg)
	if err != nil {
		log.Fatal(err)
	}

	err = rt.Start()
	if err != nil {
		log.Fatal(err)
	}

	select {}
}
