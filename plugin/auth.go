package plugin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// The exchange root user id.
const EX_ROOT_USER = "root"


// The vault plugin framework calls this method to process login requests.
func (o *ohAuthPlugin) pathAuthLogin(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	// Extract the user authentication info from the request.
	userOrg, userId, password, err := extractAndVerifyAuthCreds(d)

	if err != nil {
		o.Logger().Error(ohlog(fmt.Sprintf("error validating login for user (%s/%s), error: %v", userOrg, userId, err)))
		return nil, logical.ErrPermissionDenied
	}

	// Log that a user authentication is in progress.
	if o.Logger().IsInfo() {
		o.Logger().Info(ohlog(fmt.Sprintf("handling login for user (%s/%s)", userOrg, userId)))
	}

	// Extract the exchange URL and vault token from plugin storage. The values are stored in plugin storage when the
	// config API is invoked.
	exURL, tok, err := o.getConfig(ctx, req)
	if err != nil {
		o.Logger().Error(ohlog(fmt.Sprintf("not configured, error: %v", err)))
		return nil, logical.ErrPermissionDenied
	}

	// Verify that the caller's credentials are valid openhorizon exchange credentials.
	users, err := o.verifyCallerCredentials(exURL, userOrg, userId, password)
	if err != nil {
		o.Logger().Error(ohlog(fmt.Sprintf("user (%s/%s) is not authenticated, error: %v", userOrg, userId, err)))
		return nil, logical.ErrPermissionDenied
	}

	// The user is authenticated. Attach ACL policies to the user's token to ensure that the user can only access secrets
	// in it's org and secrets that are private to that user. The policy that is attached is different for org admins vs
	// non-admin users. Org admins can work with org wide secrets and delete user private secrets.
	foundUser := false
	foundAdminUser := false
	policyName := ""
	username := fmt.Sprintf("%s/%s", userOrg, userId)

	// Iterate through the users in the response. There should be one or none.
	for key, userInfo := range users.Users {

		// Skip users that are not the user logging in. This should never occur, just being defensive.
		if key != username {
			continue
		}

		// Ensure that the returned key is in the expected {orgid}/{username} format.
		if orgAndUsername := strings.Split(key, "/"); len(orgAndUsername) != 2 {
			o.Logger().Error(ohlog(fmt.Sprintf("returned user (%s) has unsupported format, should be org/user", key)))
			return nil, logical.ErrPermissionDenied
		}

		// Interrogate the response to find the user that we're trying to authenticate.
		if key == fmt.Sprintf("%s/%s", EX_ROOT_USER, EX_ROOT_USER) {
			// exchange root user (root/root:{pwd}), no permission
			o.Logger().Error(ohlog(fmt.Sprintf("user (root/root) is not supported")))
			return nil, logical.ErrPermissionDenied
		}

		if userInfo.HubAdmin {
			// hubAdmin, no permission
			o.Logger().Error(ohlog(fmt.Sprintf("user (%s) is a hubadmin, which is not supported", username)))
			return nil, logical.ErrPermissionDenied
		}

		if userInfo.Admin {

			// The user is an org admin.
			foundAdminUser = true
			
			// Ensure that the vault ACL policies needed by this user are defined in the vault.
			policyName, err = o.setupUserPolicies(userOrg, userId, foundAdminUser, tok)

		} else {

			// The user is a regular user.
			foundUser = true

			// Ensure that the vault ACL policies needed by this user are defined in the vault.
			policyName, err = o.setupUserPolicies(userOrg, userId, !foundUser, tok)

		}

	}

	// The authenticated user was not found in the exchange, log the error and terminate the login.
	if !foundUser && !foundAdminUser {
		o.Logger().Error(ohlog(fmt.Sprintf("user (%s/%s) was not found in the exchange", userOrg, userId)))
		return nil, logical.ErrPermissionDenied
	}

	// Log a successful authentication.
	if o.Logger().IsInfo() {
		o.Logger().Info(ohlog(fmt.Sprintf("user (%s/%s) authenticated", userOrg, userId)))
	}

	// Return the authentication results to the farmework.
	// TODO: Shorten the lease time on these
	return &logical.Response{
		Auth: &logical.Auth{
			// InternalData: map[string]interface{}{
			// 	"secret_value": "abcd1234",
			// },
			Policies: []string{policyName},
			Metadata: map[string]string{
				"admin": strconv.FormatBool(foundAdminUser),
			},
			LeaseOptions: logical.LeaseOptions{
				TTL:       30 * time.Minute,
				MaxTTL:    60 * time.Minute,
				Renewable: false,
			},
		},
	}, nil
}

// Extract the authentication info from the request and process it for correctness. The user identity
// MUST be in the standard openhorizon format: org/userid.
func extractAndVerifyAuthCreds(d *framework.FieldData) (userOrg string, userId string, password string, err error) {

	// Get the user identity from the request.
	username, ok := d.Get(AUTH_USER_KEY).(string)

	if !ok {
		err = errors.New(fmt.Sprintf("parameter %s is not a string", AUTH_USER_KEY))
		return
	}

	if username == "" {
		err = errors.New(fmt.Sprintf("%s is a required parameter for login", AUTH_USER_KEY))
		return
	}

	// Verify that the user identity conforms to the correct org/id form.
	userParts := strings.Split(username, "/")
	if len(userParts) != 2 {
		err = errors.New(fmt.Sprintf("parameter %s is not in org/user format: %s", AUTH_USER_KEY, username))
		return
	}

	userOrg = userParts[0]
	userId = userParts[1]

	// Get the token/password from the request.
	password, ok = d.Get(AUTH_TOKEN_KEY).(string)

	if !ok {
		err = errors.New(fmt.Sprintf("parameter %s is not a string", AUTH_TOKEN_KEY))
		return
	}

	if password == "" {
		err = errors.New(fmt.Sprintf("%s is a required parameter for login", AUTH_TOKEN_KEY))
		return
	}

	return
}

// Call the openhorizon exchange to validate the caller's credentials. This API call will use the caller's own credentials to verify that it can
	// retrieve the definition of it's own idenity from the exchange. This verifies that the caller's creds are good.
func (o *ohAuthPlugin) verifyCallerCredentials(exURL string, userOrg string, userId string, password string) (*GetUsersResponse, error) {

	// Log the exchange API that we are going to call.
	url := fmt.Sprintf("%v/orgs/%v/users/%v", exURL, userOrg, userId)
	user := fmt.Sprintf("%s/%s", userOrg, userId)
	apiMsg := fmt.Sprintf("%v %v", http.MethodGet, url)
	if o.Logger().IsDebug() {
		o.Logger().Debug(ohlog(fmt.Sprintf("checking exchange API %v", apiMsg)))
	}

	// Invoke the exchange API to verify the user.
	resp, err := o.InvokeExchangeWithRetry(url, user, password)

	// If there was an error invoking the HTTP API, return it.
	if err != nil {
		return nil, err
	}

	// Make sure the response reader is closed if we exit quickly.
	defer resp.Body.Close()

	// If the response code was not expected, then return the error.
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if resp.StatusCode == 401 {
			return nil, errors.New(fmt.Sprintf("unable to verify user (%v) in the exchange, HTTP code %v, either the user is undefined or the user's password is incorrect.", user, resp.StatusCode))
		} else {
			return nil, errors.New(fmt.Sprintf("unable to verify user (%v) in the exchange, HTTP code %v", user, resp.StatusCode))
		}
	}

	// Demarshal the response.
	users := new(GetUsersResponse)
	if bodyBytes, err := ioutil.ReadAll(resp.Body); err != nil {
		return nil, errors.New(fmt.Sprintf("unable to read HTTP response from %v, error: %v", apiMsg, err))
	} else if err = json.Unmarshal(bodyBytes, users); err != nil {
		return nil, errors.New(fmt.Sprintf("failed to unmarshal HTTP response from %s, error: %v", apiMsg, err))
	}

	return users, nil
}