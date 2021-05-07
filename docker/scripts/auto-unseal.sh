#!/bin/sh -x
unsealed=false

if [ "$VAULT_KEYS" == "" ];then 
  VAULT_KEYS=ibm-cp-vault-keys
fi
vault_keys=$VAULT_KEYS

while true
do
  init_status=`vault status  2>/dev/null |grep "Initialized"|awk '{print $2}'|tr -d '\r'`
  seal_status=`vault status  2>/dev/null |grep "Sealed"|awk '{print $2}'|tr -d '\r'`
  if [ "$init_status" != "true" ];then
    output="Vault is not initialized"
  elif [ "$seal_status" == "false" ];then
    output="Vault is unsealed"
    unsealed=true
  elif  [ `kubectl get secret |grep "$vault_keys" |wc -l` == 0 ]; then
    output="Unseal tokens are not found."
  else 
    keys=`kubectl get secret $vault_keys -o=jsonpath='{.data.keys}'|base64 -d`
    IFS=$',' keys=( $keys )
    for var in ${keys[@]}  
    do    
      vault operator unseal $var
    done
    output="Unseal keys were submitted."
  fi
  dataStr=`date`
  if [ "$unsealed" == "true" ];then
    echo "$dataStr [Auto-Unseal] $output"
    exit 0
  fi
  echo "$dataStr [Auto-Unseal] $output. Waiting 10 seconds for the next try."
  sleep 10
done