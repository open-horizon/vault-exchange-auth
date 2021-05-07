#!/bin/sh

export NAMESPACE=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)
#export NAMESPACE=vault
kubectl=kubectl

if [ "$VAULT_CREDENTIAL" == "" ];then 
  VAULT_CREDENTIAL=vault-default-deploy-vault-credential
fi
vault_credential=$VAULT_CREDENTIAL


#get root token
vaultToken=`$kubectl get secret $vault_credential -n $NAMESPACE -o=jsonpath={.data.token} | base64 -d`
#get vault endpoint
endpoint=`$kubectl get secret $vault_credential -n $NAMESPACE -o=jsonpath={.data.endpoint} | base64 -d`

#get all VaultAccess CRs, if autoRenewToken == true, then renew
names=`$kubectl get VaultAccess -n $NAMESPACE -o=jsonpath='{range .items[*]}{.metadata.name}{","}'`
IFS=','
read -ra namesArr <<< "$names"

echo "The number of VaultAccess instances is: ${#namesArr[@]}"

for vaultAccess in ${namesArr[@]}  
do    
  echo "------------------ VaultAccess name is: $vaultAccess ------------------"
  
  #check the status of vaultAccess, ignore the failed instances
  status=`$kubectl get VaultAccess $vaultAccess -n $NAMESPACE -o=jsonpath={.status.conditions[0].status}`
  
  if [ $status == "True" ]
  then
    echo "$vaultAccess status is: $status, proceeding"
	autoRenewToken=`$kubectl get VaultAccess $vaultAccess -n $NAMESPACE -o=jsonpath={.spec.autoRenewToken}`
	
	if [ $autoRenewToken ]
	then
	  echo "$vaultAccess autoRenewToken is set, proceeding"
	  if [ $autoRenewToken == "true" ]
	  then
	    echo "$vaultAccess autoRenewToken is: $autoRenewToken, start to renew vault token"

	    secretName=`$kubectl get VaultAccess $vaultAccess -n $NAMESPACE -o=jsonpath={.spec.secretName}`
	    echo "secret name for $vaultAccess is: $secretName"

	    accessToken=`$kubectl get secret $secretName -n $NAMESPACE -o=jsonpath={.data.token} | base64 -d`

	    status_code=$(curl -k -H "X-Vault-Token: $vaultToken" -X POST --data "{\"token\": \"$accessToken\"}" --write-out %{http_code} --silent --output /dev/null $endpoint/v1/auth/token/renew)

        if [ $status_code -eq 200 ]
		then
          echo "Successfully renewed token for VaultAccess: $vaultAccess"
        else
          echo "Error occurred when renew token for VaultAccess: $vaultAccess"
        fi
	  else
	    echo "$vaultAccess autoRenewToken is: $autoRenewToken, skip."
	  fi
	else
	  echo "$vaultAccess autoRenewToken is NOT set which means it's false, skip."
	fi
  else
    echo "$vaultAccess status is: $status, skip."
  fi
  #get the vaule of autoRenewToken
done