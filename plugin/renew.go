package plugin

import (
	"context"
	"errors"
	"fmt"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"strings"
	"time"
)

func (o *ohAuthPlugin) pathAuthRenew(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	if req.Auth == nil {
		return nil, errors.New("request auth was nil")
	}

	agbotId := req.Auth.InternalData[AGBOTID_RENEW_SECRET].(string)
	password := req.Auth.InternalData[AGBOTPW_RENEW_SECRET].(string)

	if o.Logger().IsInfo() {
		o.Logger().Info(ohlog(fmt.Sprintf("attempting token renewal for (%s)", agbotId)))
	}

	// Verify that the user identity conforms to the correct org/id form.
	agbotParts := strings.Split(agbotId, "/")
	if len(agbotParts) != 2 {
		return nil, errors.New(fmt.Sprintf("stored agbot id for renewal is not in org/id format: %s", agbotId))
	}

	agbotOrg := agbotParts[0]
	id := agbotParts[1]

	// Extract the exchange URL and vault token from plugin storage. The values are stored in plugin storage when the
	// config API is invoked.
	exURL, tok, renewal, err := o.getConfig(ctx, req)

	if err != nil {
		o.Logger().Error(ohlog(fmt.Sprintf("not configured, error: %v", err)))
		return nil, logical.ErrPermissionDenied
	}

	// Verify that the caller's credentials are valid openhorizon exchange credentials for an Agbot. Only certain errors
	// are fatal. If an explicit PermissionDenied to returned then stop authentication and return. Otherwise, the caller
	// might be a user, so the authentication process should continue.
	_, err = o.AuthenticateAsAgbot(exURL, tok, renewal, agbotOrg, id, password)

	if err == nil {
		if o.Logger().IsInfo() {
			o.Logger().Info(ohlog(fmt.Sprintf("renewed token for (%s)", agbotId)))
		}
		return framework.LeaseExtend(time.Duration(renewal)*time.Second, time.Duration(renewal*2)*time.Second, o.System())(ctx, req, d)
	} else {
		return nil, err
	}

}
