// TODO FIXME: prepend license
// Copyright (c) 2025 privateLINE, LLC.

package helpers

type JsonFileToAttach struct {
	JsonFileName     string // only a filename, not a path to file on filesystem
	JsonFileContents []byte // serialized JSON
}
