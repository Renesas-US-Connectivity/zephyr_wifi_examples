SER=J3APC0006A
set -x
rm $SER.json
curl --cacert ca_iconfig.der --cert-type DER --key-type DER --cert ${SER}_cert.der --key ${SER}_key.der https://pinnediconfig.aaecosystem.com/devices/${SER} -o ${SER}.json
cat ${SER}.json | jq

