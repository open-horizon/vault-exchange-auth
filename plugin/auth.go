package plugin

import (
	"context"
	"errors"
	"fmt"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"strings"
)

// The exchange root user id.
const EX_ROOT_USER = "root"

// The vault plugin framework calls this method to process login requests.
func (o *ohAuthPlugin) pathAuthLogin(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	// Extract the user authentication info from the request.
	userOrg, userId, password, err := extractAndVerifyAuthCreds(d)

	if err != nil {
		o.Logger().Error(ohlog(fmt.Sprintf("error validating login for user (%s/%s), error: %v", userOrg, userId, err)))
		return nil, err
	}

	// Log that a user authentication is in progress.
	if o.Logger().IsInfo() {
		o.Logger().Info(ohlog(fmt.Sprintf("handling login for user (%s/%s)", userOrg, userId)))
	}

	// Extract the exchange URL and vault token from plugin storage. The values are stored in plugin storage when the
	// config API is invoked.
	exURL, tok, renewal, err := o.getConfig(ctx, req)

	if err != nil {
		o.Logger().Error(ohlog(fmt.Sprintf("not configured, error: %v", err)))
		return nil, err
	}

	// Verify that the caller's credentials are valid openhorizon exchange credentials for an Agbot. Only certain errors
	// are fatal. If an explicit PermissionDenied to returned then stop authentication and return. Otherwise, the caller
	// might be a user, so the authentication process should continue.
	resp, err := o.AuthenticateAsAgbot(exURL, tok, renewal, userOrg, userId, password)

	if err == nil {
		return resp, nil
	} else if err == logical.ErrPermissionDenied {
		return nil, err
	}

	// The caller is not an agbot, so check if the caller is a user.

	// Verify that the caller's credentials are valid openhorizon exchange credentials for a user. All errors result in
	// PermissionDenied, because there are not other ways to check the caller's credentials.
	resp, err = o.AuthenticateAsUser(exURL, tok, userOrg, userId, password)

	if err == nil {
		return resp, nil
	} else {
		return nil, logical.ErrPermissionDenied
	}

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

type NotAuthenticatedError struct {
	Msg string
}

func (e NotAuthenticatedError) Error() string { return e.Msg }

type OtherError struct {
	Msg string
}

func (e OtherError) Error() string { return e.Msg }
