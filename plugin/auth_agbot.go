package plugin

import (
	"encoding/json"
	"fmt"
	"github.com/hashicorp/vault/sdk/logical"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const AGBOTID_RENEW_SECRET = "agbotid"
const AGBOTPW_RENEW_SECRET = "password"

// Attempt to authenticate the caller as an open horizon agbot.
func (o *ohAuthPlugin) AuthenticateAsAgbot(exURL string, tok string, renewal int, userOrg, userId, password string) (*logical.Response, error) {

	agbots, err := o.verifyAgbotCredentials(exURL, userOrg, userId, password)

	if _, ok := err.(NotAuthenticatedError); ok {
		o.Logger().Info(ohlog(fmt.Sprintf("(%s/%s) is not authenticated as an agbot: %v", userOrg, userId, err)))
		return nil, err
	} else if _, ok := err.(OtherError); ok {
		o.Logger().Error(ohlog(fmt.Sprintf("error trying to authenticate (%s/%s) as an agbot, error: %v", userOrg, userId, err)))
		return nil, err
	}

	// No errors occured, keep processing the response to ensure it is correct for an authenticated agbot.
	agbotId := fmt.Sprintf("%s/%s", userOrg, userId)
	foundAgbot := false

	// Iterate through the agbots in the response. There should be one or none.
	for key, _ := range agbots.Agbots {

		// Skip agbots that are not the agbot logging in. This should never occur, just being defensive.
		if key != agbotId {
			continue
		}

		// Ensure that the returned key is in the expected {orgid}/{agbotid} format.
		if orgAndAgbotId := strings.Split(key, "/"); len(orgAndAgbotId) != 2 {
			o.Logger().Error(ohlog(fmt.Sprintf("returned agbot (%s) has unsupported format, should be org/agbotid", key)))
			return nil, logical.ErrPermissionDenied
		}

		// The caller is an Agbot.
		foundAgbot = true

		// Ensure that the vault ACL policies needed by the agbot are defined in the vault.
		err = o.setupAgbotPolicies(tok)
		if err != nil {
			o.Logger().Error(ohlog(fmt.Sprintf("unable to setup ACL policies for agbot (%s), error: %v", agbotId, err)))
			return nil, logical.ErrPermissionDenied
		}

	}

	// The agbot was not found in the exchange, log the error and terminate the login.
	if !foundAgbot {
		o.Logger().Error(ohlog(fmt.Sprintf("Agbot (%s) was not found in the exchange", agbotId)))
		return nil, logical.ErrPermissionDenied
	}

	// Log a successful authentication.
	if o.Logger().IsInfo() {
		o.Logger().Info(ohlog(fmt.Sprintf("Agbot (%s) authenticated", agbotId)))
	}

	// Return the authentication results to the framework.
	return &logical.Response{
		Auth: &logical.Auth{
			Policies: []string{AGBOT_POLICY_NAME},
			InternalData: map[string]interface{}{
				AGBOTID_RENEW_SECRET: agbotId,
				AGBOTPW_RENEW_SECRET: password,
			},
			Metadata: map[string]string{
				"agbot": strconv.FormatBool(true),
			},
			LeaseOptions: logical.LeaseOptions{
				TTL:       time.Duration(renewal) * time.Second,
				MaxTTL:    time.Duration(renewal*2) * time.Second,
				Renewable: true,
			},
		},
	}, nil

}

// Call the openhorizon exchange to validate the caller's credentials as an Agbot. This API call will use the caller's own credentials to verify that it can
// retrieve the definition of it's own idenity from the exchange. This verifies that the caller's creds are good.
func (o *ohAuthPlugin) verifyAgbotCredentials(exURL string, userOrg string, userId string, password string) (*GetAgbotsResponse, error) {

	// Log the exchange API that we are going to call.
	url := fmt.Sprintf("%v/orgs/%v/agbots/%v", exURL, userOrg, userId)
	user := fmt.Sprintf("%s/%s", userOrg, userId)
	apiMsg := fmt.Sprintf("%v %v", http.MethodGet, url)
	if o.Logger().IsDebug() {
		o.Logger().Debug(ohlog(fmt.Sprintf("checking exchange API %v", apiMsg)))
	}

	// Invoke the exchange API to verify the user.
	resp, err := o.InvokeExchangeWithRetry(url, user, password)

	// If there was an error invoking the HTTP API, return it.
	if err != nil {
		return nil, OtherError{Msg: err.Error()}
	}

	// Make sure the response reader is closed if we exit quickly.
	defer resp.Body.Close()

	// If the response code was not expected, then return the error.
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if resp.StatusCode == 401 {
			return nil, NotAuthenticatedError{Msg: fmt.Sprintf("unable to verify agbot (%s) in the exchange, HTTP code %v, either the agbot is undefined or the agbot's password is incorrect.", userOrg, user, resp.StatusCode)}
		} else if resp.StatusCode == 404 {
			return nil, NotAuthenticatedError{Msg: fmt.Sprintf("agbot (%s) not found in the exchange, HTTP code %v", user, resp.StatusCode)}
		} else {
			return nil, OtherError{Msg: fmt.Sprintf("unable to verify agbot (%s) in the exchange, HTTP code %v", user, resp.StatusCode)}
		}
	}

	// Demarshal the response.
	agbots := new(GetAgbotsResponse)
	if bodyBytes, err := ioutil.ReadAll(resp.Body); err != nil {
		return nil, OtherError{Msg: fmt.Sprintf("unable to read HTTP response from %v, error: %v", apiMsg, err)}
	} else if err = json.Unmarshal(bodyBytes, agbots); err != nil {
		return nil, OtherError{Msg: fmt.Sprintf("failed to unmarshal HTTP response from %s, error: %v", apiMsg, err)}
	}

	return agbots, nil
}
