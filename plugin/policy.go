package plugin

import (
	"fmt"
)

// Policy name formats
const ADMIN_POLICY_NAME = `openhorizon-%s-%s-admin`
const USER_POLICY_NAME = `openhorizon-%s-%s`

// Openhorizon org admins will have these ACL policies attached.
const ADMIN_ORG_WIDE_POLICY = `path "openhorizon/%s/*" {capabilities = ["list", "read", "create", "delete", "update"]}`
const ADMIN_USER_PRIVATE_POLICY = `path "openhorizon/%s/user/*" {capabilities = ["delete"]}`

// Regular openhorizon users will have these ACL policies attached.
const NON_ADMIN_ORG_WIDE_POLICY = `path "openhorizon/%s/*" {capabilities = ["list"]}`
const USER_PRIVATE_DENY_POLICY = `path "openhorizon/%s/user/*" {capabilities = ["deny"]}`

// All supported openhorizon users will have these policies attached.
const USER_PRIVATE_POLICY = `path "openhorizon/%s/user/%s/*" {capabilities = ["list", "read", "create", "delete", "update"]}`


// Ensure that the right ACL policies exist so that they can be attached to the user's token.
func (o *ohAuthPlugin) setupUserPolicies(userOrg string, userId string, admin bool, vaultToken string) (policyName string, err error) {

	// TODO: VAULT_TOKEN env var is read by NewClient()
	o.vc.SetToken(vaultToken)

	// Get a handle to the vault system APIs
	sysVC := o.vc.Sys()

	// The admin privileges of a user can change at any time. First remove any policies that might exist but which no longer apply
	// if the admin status of the user has changed.
	oldPolicyName := getPolicyName(userOrg, userId, !admin)
	op, err := sysVC.GetPolicy(oldPolicyName)
	if err != nil {
		o.Logger().Error(ohlog(fmt.Sprintf("GetPolicy for %v failed, error: %v", oldPolicyName, err)))
		return "", err
	}

	// If there is an old policy, delete it.
	if op != "" {
		err := sysVC.DeletePolicy(oldPolicyName)
		if err != nil {
			o.Logger().Error(ohlog(fmt.Sprintf("DeletePolicy for %v failed, error: %v", oldPolicyName, err)))
			return "", err
		}

		if o.Logger().IsDebug() {
			o.Logger().Debug(ohlog(fmt.Sprintf("user (%s/%s) admin status changed, deleted policy %v", userOrg, userId, oldPolicyName)))
		}

	}

	// Create a policy for the user. If this user has been seen before, the correct policy might already exist.
	policyName = getPolicyName(userOrg, userId, admin)

	np, err :=sysVC.GetPolicy(policyName)

	if err != nil {
		o.Logger().Error(ohlog(fmt.Sprintf("GetPolicy for %v failed, error: %v", policyName, err)))
		return "", err
	}

	// If a policy does not already exist for this user, create it.
	if np == "" {
		// Construct an in-memory policy definition specifically for this user.
		policyString := getPolicyString(userOrg, userId, admin)

		if o.Logger().IsDebug() {
			o.Logger().Debug(ohlog(fmt.Sprintf("constructed policy %v for user (%s/%s)", policyString, userOrg, userId)))
		}

		// Add the policy to the vault.
		err := sysVC.PutPolicy(policyName, policyString)
		if err != nil {
			o.Logger().Error(ohlog(fmt.Sprintf("PutPolicy for %v failed, error: %v", policyName, err)))
			return "", err
		}

		// Log successful creation of the policy.
		if o.Logger().IsInfo() {
			o.Logger().Info(ohlog(fmt.Sprintf("PutPolicy for %v successful", policyName)))
		}

	}

	return
}

// Construct a policy name based on the user and their admin status.
func getPolicyName(userOrg string, userId string, admin bool) (policyName string) {
	if admin {
		policyName = fmt.Sprintf(ADMIN_POLICY_NAME, userOrg, userId)
	} else {
		policyName = fmt.Sprintf(USER_POLICY_NAME, userOrg, userId)
	}
	return
}

// Construct the ACL policy rules based on the user and their admin status.
func getPolicyString(userOrg string, userId string, admin bool) (policyString string) {
	if admin {
		adminPolicy := fmt.Sprintf(ADMIN_ORG_WIDE_POLICY, userOrg)
		adminUserPrivatePolicy := fmt.Sprintf(ADMIN_USER_PRIVATE_POLICY, userOrg)
		userPrivatePolicy := fmt.Sprintf(USER_PRIVATE_POLICY, userOrg, userId)
		policyString = fmt.Sprintf("%s %s %s", adminPolicy, adminUserPrivatePolicy, userPrivatePolicy)
	} else {
		nonAdminPolicy := fmt.Sprintf(NON_ADMIN_ORG_WIDE_POLICY, userOrg)
		adminUserPrivateDeny := fmt.Sprintf(USER_PRIVATE_DENY_POLICY, userOrg)
		userPrivatePolicy := fmt.Sprintf(USER_PRIVATE_POLICY, userOrg, userId)
		policyString = fmt.Sprintf("%s %s %s", nonAdminPolicy, adminUserPrivateDeny, userPrivatePolicy)
	}

	return
}