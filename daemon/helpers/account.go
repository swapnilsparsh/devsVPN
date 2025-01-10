// Copyright (c) 2024 privateLINE, LLC.

package helpers

import "regexp"

// TODO FIXME: Vlad - remove support for prefix "a-", once backend no longer supports account IDs starting with "a-"
var AccountIdRegex = regexp.MustCompile("^(a-)?([1-9A-HJ-NP-Z]{4}-){2}[1-9A-HJ-NP-Z]{4}$")

func IsAValidAccountID(accountID string) bool {
	return AccountIdRegex.MatchString(accountID)
}
