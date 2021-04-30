package plugin

import (
	"context"
	"errors"
	"fmt"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const EXCHANGE_URL_STORAGE_KEY = "exchange-url"
const VAULT_TOKEN_STORAGE_KEY = "agbot-vault-token"

func (o *ohAuthPlugin) pathConfig(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	url := d.Get(CONFIG_EXCHANGE_URL_KEY).(string)
	if url == "" {
		return nil, errors.New(ohlog(fmt.Sprintf("%s is a required parameter", CONFIG_EXCHANGE_URL_KEY)))
	}
	req.Storage.Put(ctx, &logical.StorageEntry{Key:EXCHANGE_URL_STORAGE_KEY, Value:[]byte(url)})

	token := d.Get(CONFIG_TOKEN_KEY).(string)
	if token == "" {
		return nil, errors.New(ohlog(fmt.Sprintf("%s is a required parameter", CONFIG_TOKEN_KEY)))
	}
	req.Storage.Put(ctx, &logical.StorageEntry{Key:VAULT_TOKEN_STORAGE_KEY, Value:[]byte(token)})

	// TODO: Don't log the token

	if o.Logger().IsInfo() {
		o.Logger().Info(ohlog(fmt.Sprintf("config is set, url: %v, token: %v", url, token)))
	}

	return nil, nil
}

// Extract the exchange URL and vault token from plugin storage.
func (o *ohAuthPlugin) getConfig(ctx context.Context, req *logical.Request) (exURL string, token string, err error) {

	var url *logical.StorageEntry

	url, err = req.Storage.Get(ctx, EXCHANGE_URL_STORAGE_KEY)
	if err != nil {
		return
	}

	if url == nil || len(url.Value) == 0 {
		err = errors.New(fmt.Sprintf("%s is not set. Use the /config API to configure the plugin.", CONFIG_EXCHANGE_URL_KEY))
		return
	}

	exURL = string(url.Value)

	var tok *logical.StorageEntry

	// Extract the agbot vault token from plugin storage.
	tok, err = req.Storage.Get(ctx, VAULT_TOKEN_STORAGE_KEY)
	if err != nil {
		return
	}

	if tok == nil || len(tok.Value) == 0 {
		err = errors.New(fmt.Sprintf("%s is not set. Use the /config API to configure the plugin.", CONFIG_TOKEN_KEY))
	}

	token = string(tok.Value)

	return
}