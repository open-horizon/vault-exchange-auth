package plugin

import(
	"context"
	"errors"
	"fmt"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"strconv"
	"strings"
)

func (o *ohAuthPlugin) pathACLUpdate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// Extract the user authentication info from the request.
	userOrg, userId, password, err := extractAndVerifyAuthCreds(d)

	if err != nil {
		o.Logger().Error(ohlog(fmt.Sprintf("error validating agbot (%s/%s), error: %v", userOrg, userId, err)))
		return nil, err
	}

	// Log that a user authentication is in progress.
	if o.Logger().IsInfo() {
		o.Logger().Info(ohlog(fmt.Sprintf("handling acl update from agbot (%s/%s)", userOrg, userId)))
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
	_, err = o.AuthenticateAsAgbot(exURL, tok, renewal, userOrg, userId, password)

	if err != nil {
		return nil, err
	}

	aclMap := getStringMap(d.Get(ACL_USER_CONTENT).(map[string]interface{}))
	userAdminMap := getStringMap(d.Get(ACL_USER_ADMIN).(map[string]interface{}))

	for user, list := range aclMap {
		// Verify that the user identity conforms to the correct org/id form.
		userParts := strings.Split(user, "/")
		if len(userParts) != 2 {
			return nil, errors.New(fmt.Sprintf("parameter %s is not in org/user format: %s", AUTH_USER_KEY, user))
		}

		aclUserOrg := userParts[0]
		aclUserId := userParts[1]

		admin := false
		if adminStr, ok := userAdminMap[user]; ok {
			admin, _ = strconv.ParseBool(adminStr)
		}

		polName, err := o.setupUserPolicies(aclUserOrg, aclUserId, admin, tok, list)
		if err != nil {
         	       return nil, err
        	}
		fmt.Sprintf("%v",polName)
	}
	return nil, nil
}

func getStringMap(original map[string]interface{}) map[string]string {
	strMap := map[string]string{}
	for key, val := range(original) {
		strMap[key] = fmt.Sprintf("%v", val)
	}
	return strMap
}
