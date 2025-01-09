// TODO FIXME: prepend license
// Copyright (c) 2024 privateLINE, LLC.

package helpers

import (
	"reflect"
	"regexp"
	"syscall"
)

var (
	ZeroGUID = syscall.GUID{}
)

// (?i) for case-insensitive matching
var GuidRegex = regexp.MustCompile("(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")

func IsAGuidString(potentialGUID string) bool {
	return GuidRegex.MatchString(potentialGUID)
}

func IsZeroGUID(guid syscall.GUID) bool {
	return reflect.DeepEqual(guid, ZeroGUID)
}
