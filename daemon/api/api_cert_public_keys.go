package api

// As of July 2024, one TLS cert covers privateline.io and *.privateline.io DNS names
//
// You can generate API cert hashes with daemon/References/common/scripts/generateAPIPrivateLineHashes.sh

// APIPrivateLineHashes - base64-encoded SHA256 hashes for 'api.privateline.io' server public keys (in use for certificate key pinning)
// Certs good as of Jan 2025

var APIPrivateLineHashes = []string{
	"u4GSL0S1V8jcHJ3sJ07ehNMu3uALbeiwUxL+P/OZCXc=", // deskapi.privateline.io, api.privateline.io, sso.privateline.io
	"KJyZJqESixPI7jPLs0/8P2q6kI4h5kXWIkoxybZ/gzM=", // api.privateline.io old cert

	"H84WASAGlih/MAB89DhXu+D5HdKG6hfHudZrEN9RQ3c=",	// api.privateline.dev, sso.privateline.dev
	"3/INJ5mVSZ/bndP0j6irtFHJ3M+1PVr0+/s91l8JKzM=", // older dev cert hash
}

// UpdatePrivateLineHashes - base64-encoded SHA256 hashes for 'repo.privateline.io' server public keys (in use for certificate key pinning)
var UpdatePrivateLineHashes = []string{
	"mtvgFSaN8RgU8gXFOgj/m1hXSWJsh8Wie+JV2ZQXH2o=",
	"K7rZOrXHknnsEhUH8nLL4MZkejquUuIvOIr6tCa0rbo=",
}
