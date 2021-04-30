package main

import (
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/plugin"
	ohplugin "github.com/open-horizon/vault-exchange-auth/plugin"
	"log"
	"os"
)

// This plugin provides authentication support for openhorizon users within the vault.
//
// It uses the Vault's framework to interact with the plugin system.
//
// This plugin must be configured by a vault admin through the /config API. Without the config, the plugin
// is unable to function properly.

func main() {
	apiClientMeta := &api.PluginAPIClientMeta{}
	flags := apiClientMeta.FlagSet()
	flags.Parse(os.Args[1:])

	tlsConfig := apiClientMeta.GetTLSConfig()
	tlsProviderFunc := api.VaultPluginTLSProvider(tlsConfig)

	if err := plugin.Serve(&plugin.ServeOpts{
		BackendFactoryFunc: ohplugin.Factory,
		TLSProviderFunc:    tlsProviderFunc,
	}); err != nil {
		log.Fatal(err)
	}
}