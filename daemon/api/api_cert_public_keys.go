package api

// As of July 2024, one TLS cert covers privateline.io and *.privateline.io DNS names
//
// You can generate API cert hashes with daemon/References/common/scripts/generateAPIPrivateLineHashes.sh

// APIPrivateLineHashes - base64-encoded SHA256 hashes for 'api.privateline.io' server public keys (in use for certificate key pinning)
var APIPrivateLineHashes = []string{
	"mtvgFSaN8RgU8gXFOgj/m1hXSWJsh8Wie+JV2ZQXH2o=",
	"K7rZOrXHknnsEhUH8nLL4MZkejquUuIvOIr6tCa0rbo=",
}

// UpdatePrivateLineHashes - base64-encoded SHA256 hashes for 'repo.privateline.io' server public keys (in use for certificate key pinning)
var UpdatePrivateLineHashes = []string{
	"mtvgFSaN8RgU8gXFOgj/m1hXSWJsh8Wie+JV2ZQXH2o=",
	"K7rZOrXHknnsEhUH8nLL4MZkejquUuIvOIr6tCa0rbo=",
}
