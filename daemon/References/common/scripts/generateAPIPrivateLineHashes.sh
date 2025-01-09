#! /bin/bash

# Copyright (c) 2024 privateLINE, LLC.

# !!! IMPORTANT !!!: Don't just trust the downloaded certificates blindly. Verify that downloaded certificates match the actual, expected certificates - ask Deepak.

# Fetches the TLS certificates and calculates the base64-encoded SHA-256 hashes of their public keys.
# Those go into daemon/api/api_cert_public_keys.go

[[ $BASH_ARGC -eq 2 ]]																		|| { echo -e "USAGE: $0 <hostname> <port>\n\tFor example: $0 api.privateline.io 443"; exit 0; }

HOST=$1
PORT=$2

EXPECTED_CN="privateline\.(io|dev)"

WORKDIR=`mktemp -td privateline_cert_hashesXXXX`
pushd "$WORKDIR"																			|| { RET=$?; >&2 echo "ERROR $RET pushd $WORKDIR"; exit $RET; }

# Uncomment the trap if you want the directory with tempotary files to be deleted at the end
#trap "[ ! -z "$WORKDIR" ] && rm -rf \"$WORKDIR\"" EXIT

# Download certificates and save them to .pem files
echo | openssl s_client -showcerts -servername $HOST -connect $HOST:$PORT |\
	awk '/-----BEGIN/{f="cert."(n++)".pem"} f{print>f} /-----END/{f=""}'					|| { RET=$?; >&2 echo "ERROR $RET fetching certs"; exit $RET; }

BASE64_ENCODED_HASHES=()
for CERT in cert.*.pem ; do
	echo "--------------------------------------------------------------------------------------------------------------------------------"
	CERT_BASENAME=`basename $CERT .pem`
	PUBKEY="${CERT_BASENAME}.publickey.der"

	# Only process if Subject includes privateline.io
	SUBJ=`openssl x509 -noout -subject -in $CERT`
	echo -e "Subject:\t$SUBJ"
	echo $SUBJ | grep -Eq "${EXPECTED_CN}" || { echo "Subject doesn't contain '${EXPECTED_CN}', skipping"; continue; }

	# Extract public key from certificate in DER format
	openssl x509 -in $CERT -inform pem -pubkey -noout |\
		openssl enc -base64 -d > $PUBKEY													|| { RET=$?; >&2 echo "ERROR $RET extracting public key"; exit $RET; }

	# Print SHA-256 hash of the public key
	sha256sum $PUBKEY

	# Print base64 encoding of the hash
	BASE64_ENCODED_HASH=`openssl sha256 -binary $PUBKEY | base64 --wrap=0`					|| { RET=$?; >&2 echo "ERROR $RET base64-encoding SHA256 hash of public key"; exit $RET; }
	echo -e "Base64-encoded SHA-256 hash of public key $PUBKEY:\t\t${BASE64_ENCODED_HASH}"
	BASE64_ENCODED_HASHES+=("${BASE64_ENCODED_HASH}")
done

echo "--------------------------------------------------------------------------------------------------------------------------------"
echo "!!! IMPORTANT !!! Don't just trust the downloaded certificates blindly. Verify that downloaded certificates match the actual, expected certificates - ask Deepak !!!"
echo "--------------------------------------------------------------------------------------------------------------------------------"

echo "Now enter the base64-encoded hashes into daemon/api/api_cert_public_keys.go"
echo -e "For example:\n"
echo "var APIPrivateLineHashes = []string{"
for HASH in "${BASE64_ENCODED_HASHES[@]}" ; do
	echo -e "\t\"$HASH\","
done
echo "}"
