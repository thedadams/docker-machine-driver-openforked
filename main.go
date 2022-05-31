package main

import (
	"github.com/rancher/machine/libmachine/drivers/plugin"
	"github.com/thedadams/docker-machine-driver-openforked/openforked"
)

func main() {
	plugin.RegisterDriver(openforked.NewDriver("", ""))
}
