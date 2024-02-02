package plugin

import (
	"fmt"
)

// Policy name formats
const AGBOT_POLICY_NAME = `openhorizon-agbot`
const ADMIN_POLICY_NAME = `openhorizon-%s-%s-admin`
const USER_POLICY_NAME = `openhorizon-%s-%s`

// Openhorizon agbots will have these ACL policies attached.
const AGBOT_POLICY = `path "openhorizon/*" {capabilities = ["list","read"]}`

// Openhorizon org admins will have these ACL policies attached.
const ADMIN_ORG_WIDE_POLICY1 = `path "openhorizon/data/%s/*" {capabilities = ["create", "update", "read"]}`
const ADMIN_ORG_WIDE_POLICY2 = `path "openhorizon/metadata/%s/*" {capabilities = ["list", "read", "delete"]}`

// Regular openhorizon users will have these ACL policies attached.
// note: USER_PRIVATE_DENY_POLICY1 is also given to admins to prevent them from being able to read 
// other user's private secrets
const NON_ADMIN_ORG_WIDE_POLICY = `path "openhorizon/metadata/%s/*" {capabilities = ["list", "read"]}`
const USER_PRIVATE_DENY_POLICY1 = `path "openhorizon/data/%s/user/*" {capabilities = ["deny"]}`
const USER_PRIVATE_DENY_POLICY2 = `path "openhorizon/metadata/%s/user/*" {capabilities = ["deny"]}`

// All supported openhorizon users will have these policies attached.
const USER_PRIVATE_POLICY1 = `path "openhorizon/data/%s/user/%s/*" {capabilities = ["create", "update", "read"]}`
const USER_PRIVATE_POLICY2 = `path "openhorizon/metadata/%s/user/%s/*" {capabilities = ["list", "read", "delete"]}`
const USER_PRIVATE_POLICY3 = `path "openhorizon/metadata/%s/user/%s" {capabilities = ["list"]}`

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

		if o.Logger().IsInfo() {
			o.Logger().Info(ohlog(fmt.Sprintf("user (%s/%s) admin status changed, deleted old policy %v", userOrg, userId, oldPolicyName)))
		}

	}

	// Create a policy for the user. Make sure this new policy does not already exist.
	policyName = getPolicyName(userOrg, userId, admin)

	np, err := sysVC.GetPolicy(policyName)

	if err != nil {
		o.Logger().Error(ohlog(fmt.Sprintf("GetPolicy for %v failed, error: %v", policyName, err)))
		return "", err
	}

	// If there is a new policy, delete it.
	if np != "" {
		err := sysVC.DeletePolicy(np)
		if err != nil {
			o.Logger().Error(ohlog(fmt.Sprintf("DeletePolicy for %v failed, error: %v", np, err)))
			return "", err
		}

		if o.Logger().IsInfo() {
			o.Logger().Info(ohlog(fmt.Sprintf("Deleted policy %v for user (%s/%s)", np, userOrg, userId)))
		}

	}

	// Create the ACL policy for this user.

	// Construct an in-memory policy definition specifically for this user.
	policyString := getPolicyString(userOrg, userId, admin)

	if o.Logger().IsInfo() {
		o.Logger().Info(ohlog(fmt.Sprintf("constructed policy %v for user (%s/%s)", policyString, userOrg, userId)))
	}

	// Add the policy to the vault.
	if err := sysVC.PutPolicy(policyName, policyString); err != nil {
		o.Logger().Error(ohlog(fmt.Sprintf("PutPolicy for %v failed, error: %v", policyName, err)))
		return "", err
	}

	// Log successful creation of the policy.
	if o.Logger().IsInfo() {
		o.Logger().Info(ohlog(fmt.Sprintf("PutPolicy for %v successful", policyName)))
	}

	return
}

// Ensure that the right ACL policies exist so that they can be attached to the user's token.
func (o *ohAuthPlugin) setupAgbotPolicies(vaultToken string) (err error) {

	o.vc.SetToken(vaultToken)

	// Get a handle to the vault system APIs
	sysVC := o.vc.Sys()

	// Create a policy for the agbot. If the agbot has been seen before, the correct policy might already exist.
	np, err := sysVC.GetPolicy(AGBOT_POLICY_NAME)

	if err != nil {
		o.Logger().Error(ohlog(fmt.Sprintf("GetPolicy for %v failed, error: %v", AGBOT_POLICY_NAME, err)))
		return err
	}

	// If a policy does not already exist for the agbot, create it.
	if np == "" {

		// Add the policy to the vault.
		err := sysVC.PutPolicy(AGBOT_POLICY_NAME, AGBOT_POLICY)
		if err != nil {
			o.Logger().Error(ohlog(fmt.Sprintf("PutPolicy for %v failed, error: %v", AGBOT_POLICY_NAME, err)))
			return err
		}

		// Log successful creation of the policy.
		if o.Logger().IsInfo() {
			o.Logger().Info(ohlog(fmt.Sprintf("PutPolicy for %v successful", AGBOT_POLICY_NAME)))
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
		adminPolicy1 := fmt.Sprintf(ADMIN_ORG_WIDE_POLICY1, userOrg)
		adminPolicy2 := fmt.Sprintf(ADMIN_ORG_WIDE_POLICY2, userOrg)
		userPrivatePolicy1 := fmt.Sprintf(USER_PRIVATE_POLICY1, userOrg, userId)
		userPrivateDenyPolicy := fmt.Sprintf(USER_PRIVATE_DENY_POLICY1, userOrg)
		policyString = fmt.Sprintf("%s %s %s %s", adminPolicy1, adminPolicy2, userPrivatePolicy1, userPrivateDenyPolicy)
	} else {
		nonAdminPolicy := fmt.Sprintf(NON_ADMIN_ORG_WIDE_POLICY, userOrg)
		adminUserPrivateDeny1 := fmt.Sprintf(USER_PRIVATE_DENY_POLICY1, userOrg)
		adminUserPrivateDeny2 := fmt.Sprintf(USER_PRIVATE_DENY_POLICY2, userOrg)
		userPrivatePolicy1 := fmt.Sprintf(USER_PRIVATE_POLICY1, userOrg, userId)
		userPrivatePolicy2 := fmt.Sprintf(USER_PRIVATE_POLICY2, userOrg, userId)
		userPrivatePolicy3 := fmt.Sprintf(USER_PRIVATE_POLICY3, userOrg, userId)
		policyString = fmt.Sprintf("%s %s %s %s %s %s", nonAdminPolicy, adminUserPrivateDeny1, adminUserPrivateDeny2, userPrivatePolicy1, userPrivatePolicy2, userPrivatePolicy3)
	}

	return
}
