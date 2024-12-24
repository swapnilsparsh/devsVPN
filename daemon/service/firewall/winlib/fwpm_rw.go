// Copyright (c) 2021 The Inet.Af AUTHORS. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build windows
// +build windows

// TODO: Vlad: refactor all/much our FWPM interfacing to Tailscale interface

package winlib

import (
	"reflect"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var zeroGUID = windows.GUID{}

const (
	ERROR_FWP_E_SUBLAYER_NOT_FOUND = 0x80320007

	// fwpmSession0FlagDynamic = 1
)

// LayerID identifies a WFP layer.
type LayerID windows.GUID

// SublayerID identifies a WFP sublayer.
type SublayerID windows.GUID

// FieldID identifies a WFP layer field.
type FieldID windows.GUID

//go:notinheap
type fwpmDisplayData0 struct {
	Name        *uint16
	Description *uint16
}

// type fwpmSession0Flags uint32

//go:notinheap
// type fwpmSession0 struct {
// 	SessionKey           windows.GUID
// 	DisplayData          fwpmDisplayData0
// 	Flags                fwpmSession0Flags
// 	TxnWaitTimeoutMillis uint32
// 	ProcessID            uint32
// 	SID                  *windows.SID
// 	Username             *uint16
// 	KernelMode           uint8
// }

// type authnService uint32

// const (
// 	authnServiceWinNT   authnService = 0xa
// 	authnServiceDefault authnService = 0xffffffff
// )

// //go:notinheap
// type fwpmLayerEnumTemplate0 struct {
// 	reserved uint64
// }

// //go:notinheap
// type fwpmLayer0 struct {
// 	LayerKey           LayerID
// 	DisplayData        fwpmDisplayData0
// 	Flags              uint32
// 	NumFields          uint32
// 	Fields             *fwpmField0
// 	DefaultSublayerKey SublayerID
// 	LayerID            uint16
// }

// type fwpmFieldType uint32

// const (
// 	fwpmFieldTypeRawData   fwpmFieldType = iota // no special semantics
// 	fwpmFieldTypeIPAddress                      // data is an IP address
// 	fwpmFieldTypeFlags                          // data is a flag bitfield
// )

// type dataType uint32

// const (
// 	dataTypeEmpty                  dataType = 0
// 	dataTypeUint8                  dataType = 1
// 	dataTypeUint16                 dataType = 2
// 	dataTypeUint32                 dataType = 3
// 	dataTypeUint64                 dataType = 4
// 	dataTypeByteArray16            dataType = 11
// 	dataTypeByteBlob               dataType = 12
// 	dataTypeSID                    dataType = 13
// 	dataTypeSecurityDescriptor     dataType = 14
// 	dataTypeTokenInformation       dataType = 15
// 	dataTypeTokenAccessInformation dataType = 16
// 	dataTypeArray6                 dataType = 18
// 	dataTypeBitmapIndex            dataType = 19
// 	dataTypeV4AddrMask             dataType = 256
// 	dataTypeV6AddrMask             dataType = 257
// 	dataTypeRange                  dataType = 258
// )

// Types not implemented, because WFP doesn't seem to use them.
// dataTypeInt8 dataType = 5
// dataTypeInt16 dataType = 6
// dataTypeInt32 dataType = 7
// dataTypeInt64 dataType = 8
// dataTypeFloat dataType = 9
// dataTypeDouble dataType = 10
// dataTypeUnicodeString dataType = 17
// dataTypeBitmapArray64 dataType = 20

//go:notinheap
// type fwpmField0 struct {
// 	FieldKey *FieldID
// 	Type     fwpmFieldType
// 	DataType dataType
// }

//go:notinheap
// type fwpmSublayerEnumTemplate0 struct {
// 	ProviderKey *windows.GUID
// }

//go:notinheap
type fwpByteBlob struct {
	Size uint32
	Data *uint8
}

type fwpmSublayerFlags uint32

const fwpmSublayerFlagsPersistent fwpmSublayerFlags = 1

//go:notinheap
type FwpmSublayer0 struct {
	SublayerKey  SublayerID
	DisplayData  fwpmDisplayData0
	Flags        fwpmSublayerFlags
	ProviderKey  *windows.GUID
	ProviderData fwpByteBlob
	Weight       uint16
}

var (
	modfwpuclnt = windows.NewLazySystemDLL("fwpuclnt.dll")
	// modole32    = windows.NewLazySystemDLL("ole32.dll")

	procFwpmFreeMemory0       = modfwpuclnt.NewProc("FwpmFreeMemory0")
	procFwpmSubLayerGetByKey0 = modfwpuclnt.NewProc("FwpmSubLayerGetByKey0")

	// procStringFromGUID2 = modole32.NewProc("StringFromGUID2")
)

func FwpmFreeMemory0(p *struct{}) {
	syscall.Syscall(procFwpmFreeMemory0.Addr(), 1, uintptr(unsafe.Pointer(p)), 0, 0)
}

func FwpmSubLayerGetByKey0(engineHandle windows.Handle, guid SublayerID, sublayerPP **FwpmSublayer0) (found bool, err error) {
	r0, _, _ := syscall.Syscall(procFwpmSubLayerGetByKey0.Addr(), 3, uintptr(engineHandle), uintptr(unsafe.Pointer(&guid)), uintptr(unsafe.Pointer(sublayerPP)))
	if r0 == ERROR_FWP_E_SUBLAYER_NOT_FOUND {
		return false, nil
	} else if r0 != 0 {
		return false, checkDefaultAPIResp(r0, nil)
	}

	return true, nil
}

// WfpFindSubLayerWithMaxWeight looks for a sublayer with weight 0xFFFF (maximum possible weight). If found - returns its handle, else returns null.
func WfpFindSubLayerWithMaxWeight(engine syscall.Handle) (found bool, sublayerKey syscall.GUID, err error) {
	defer catchPanic(&err)

	var a arena
	defer a.Dispose()

	guidPtr := toGUID(&a, zeroGUID)

	retval, _, err := fWfpFindSubLayerWithMaxWeight.Call(uintptr(engine), uintptr(unsafe.Pointer(guidPtr)))
	if err = checkDefaultAPIResp(retval, err); err != nil || reflect.DeepEqual(*guidPtr, zeroGUID) {
		return false, syscall.GUID{}, err
	}

	return true, syscall.GUID(*guidPtr), nil
}

// toGUID returns an arena-allocated copy of guid.
func toGUID(a *arena, guid windows.GUID) *windows.GUID {
	// if guid == (windows.GUID{}) {
	// 	return nil
	// }
	ret := (*windows.GUID)(a.Alloc(unsafe.Sizeof(guid)))
	*ret = guid
	return ret
}

// func stringFromGUID2(rguid *windows.GUID, lpsz *uint16, cchMax int32) (chars int32) {
// 	r0, _, _ := syscall.Syscall(procStringFromGUID2.Addr(), 3, uintptr(unsafe.Pointer(rguid)), uintptr(unsafe.Pointer(lpsz)), uintptr(cchMax))
// 	chars = int32(r0)
// 	return
// }

// func GUIDToString(guid windows.GUID) string {
// 	return guid.String()
// }

// // String returns the canonical string form of the GUID,
// // in the form of "{XXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}".
// func (guid windows.GUID) String() string {
// 	var str [100]uint16
// 	chars := stringFromGUID2(&guid, &str[0], int32(len(str)))
// 	if chars <= 1 {
// 		return ""
// 	}
// 	return string(utf16.Decode(str[:chars-1]))
// }
