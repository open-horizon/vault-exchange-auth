package plugin

import (
	"context"
	"errors"
	"fmt"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"strconv"
)

const EXCHANGE_URL_STORAGE_KEY = "exchange-url"
const VAULT_TOKEN_STORAGE_KEY = "agbot-vault-token"
const AGBOT_RENEWAL_KEY = "agbot-renewal"
const VAULT_APIURL_STORAGE_KEY = "vault-url"

const DEFAULT_RENEWAL_RATE = 300
const DEFAULT_APIURL = "http://localhost:8200"

func (o *ohAuthPlugin) pathConfig(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	// Validate that the exchange URL is reachable.
	if o.Logger().IsInfo() {
		o.Logger().Info(ohlog("processing config update"))
	}

	url := d.Get(CONFIG_EXCHANGE_URL_KEY).(string)
	if url == "" {
		return nil, errors.New(ohlog(fmt.Sprintf("%s is a required parameter", CONFIG_EXCHANGE_URL_KEY)))
	}

	// Attempt to verify that the exchange URL is good by hitting the version API. This is the only unauthenticated API.
	fullURL := fmt.Sprintf("%v/admin/version", url)
	resp, err := o.InvokeExchangeWithRetry(fullURL, "", "")

	// If there was an error invoking the HTTP API, return it.
	if err != nil {
		return nil, OtherError{Msg: fmt.Sprintf("unable to verify exchange URL (%s), error: %v", url, err)}
	}

	// Make sure the response reader is closed if we exit quickly.
	defer resp.Body.Close()

	// If the response code was not expected, then return the error.
	if resp.StatusCode != 200 {
		return nil, OtherError{Msg: fmt.Sprintf("unable to verify exchange URL (%s), HTTP code %v", url, resp.StatusCode)}
	}

	req.Storage.Put(ctx, &logical.StorageEntry{Key: EXCHANGE_URL_STORAGE_KEY, Value: []byte(url)})

	// Store the vault token used to setup the vault.
	token := d.Get(CONFIG_TOKEN_KEY).(string)
	if token == "" {
		return nil, errors.New(ohlog(fmt.Sprintf("%s is a required parameter", CONFIG_TOKEN_KEY)))
	}
	req.Storage.Put(ctx, &logical.StorageEntry{Key: VAULT_TOKEN_STORAGE_KEY, Value: []byte(token)})

	// Store the agbot login renewal rate.
	renewal := d.Get(CONFIG_AGBOT_RENEWAL_KEY).(int)
	if renewal == 0 {
		renewal = DEFAULT_RENEWAL_RATE
	}
	req.Storage.Put(ctx, &logical.StorageEntry{Key: AGBOT_RENEWAL_KEY, Value: []byte(strconv.Itoa(renewal))})

	// Store the vault API URL used by the plugin to invoke vault APIs.
	vaultAPIURL := d.Get(CONFIG_VAULT_API_KEY).(string)
	if vaultAPIURL == "" {
		vaultAPIURL = DEFAULT_APIURL
	}
	req.Storage.Put(ctx, &logical.StorageEntry{Key: VAULT_APIURL_STORAGE_KEY, Value: []byte(token)})

	// Set the URL into the vault client object.
	o.vc.SetAddress(vaultAPIURL)

	// Log the config
	if o.Logger().IsInfo() {
		o.Logger().Info(ohlog(fmt.Sprintf("config is set, exchange url: %v, token: ********, renewal: %v, vault API URL: %v", url, renewal, vaultAPIURL)))
	}

	return nil, nil
}

// Extract the exchange URL and vault token from plugin storage.
func (o *ohAuthPlugin) getConfig(ctx context.Context, req *logical.Request) (exURL string, token string, renewalRate int, err error) {

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

	var renewal *logical.StorageEntry

	// Extract the agbot renewal rate from plugin storage.
	renewal, err = req.Storage.Get(ctx, AGBOT_RENEWAL_KEY)
	if err != nil {
		return
	}

	if renewal == nil || len(tok.Value) == 0 {
		err = errors.New(fmt.Sprintf("%s is not set. Use the /config API to configure the plugin.", AGBOT_RENEWAL_KEY))
	}

	rr, err := strconv.Atoi(string(renewal.Value))
	if err != nil {
		renewalRate = DEFAULT_RENEWAL_RATE
	} else {
		renewalRate = rr
	}

	return
}
