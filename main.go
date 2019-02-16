package main

import (
	"github.com/hashicorp/terraform/plugin"
	"github.com/payscrypt/terraform-provider-wireguard/wireguard"
)

func main() {
	plugin.Serve(&plugin.ServeOpts{
		ProviderFunc: wireguard.Provider})
}
