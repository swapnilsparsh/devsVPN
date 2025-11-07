// TODO: FIXME: prepend license
// Copyright (c) 2025 privateLINE, LLC.

package helpers

import (
	"reflect"
	"runtime"
)

func GetFunctionName(i interface{}) string {
	return runtime.FuncForPC(reflect.ValueOf(i).Pointer()).Name()
}
