//
//  Daemon for IVPN Client Desktop
//  https://github.com/swapnilsparsh/devsVPN
//
//  Created by Stelnykovych Alexandr.
//  Copyright (c) 2023 IVPN Limited.
//
//  This file is part of the Daemon for IVPN Client Desktop.
//
//  The Daemon for IVPN Client Desktop is free software: you can redistribute it and/or
//  modify it under the terms of the GNU General Public License as published by the Free
//  Software Foundation, either version 3 of the License, or (at your option) any later version.
//
//  The Daemon for IVPN Client Desktop is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
//  or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
//  details.
//
//  You should have received a copy of the GNU General Public License
//  along with the Daemon for IVPN Client Desktop. If not, see <https://www.gnu.org/licenses/>.
//

//go:build windows
// +build windows

package winlib

import (
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
)

func preApply(match FwpMatchType, filter syscall.Handle, conditionIndex uint32, fieldKey syscall.GUID) error {
	if err := FWPMFILTERSetConditionFieldKey(filter, conditionIndex, fieldKey); err != nil {
		return fmt.Errorf("condition pre-apply: failed to set filter condition : %w", err)
	}
	return FWPMFILTERSetConditionMatchType(filter, conditionIndex, match)
}

// ------------------------------------------------------------------------------------------------------

// ConditionAleAppID - new condition type implementation
type ConditionAleAppID struct {
	Match            FwpMatchType
	FullPathTobinary string
}

// Apply applies the filter
func (c *ConditionAleAppID) Apply(filter syscall.Handle, conditionIndex uint32) error {
	if err := preApply(c.Match, filter, conditionIndex, FwpmConditionAleAppID); err != nil {
		return fmt.Errorf("condition pre-apply error: %w", err)
	}
	return FWPMFILTERSetConditionBlobString(filter, conditionIndex, c.FullPathTobinary)
}

// ------------------------------------------------------------------------------------------------------

// ConditionAleEffectiveName - new condition type implementation
// type ConditionAleEffectiveName struct {
// 	Match   FwpMatchType
// 	DnsName string
// }

// Apply applies the filter
// func (c *ConditionAleEffectiveName) Apply(filter syscall.Handle, conditionIndex uint32) error {
// 	if err := preApply(c.Match, filter, conditionIndex, FwpmConditionAleEffectiveName); err != nil {
// 		return fmt.Errorf("condition pre-apply error: %w", err)
// 	}
// 	return FWPMFILTERSetConditionBlobString(filter, conditionIndex, c.DnsName)
// }

// ------------------------------------------------------------------------------------------------------

// ConditionPeerName - new condition type implementation
// type ConditionPeerName struct {
// 	Match   FwpMatchType
// 	DnsName string
// }

// Apply applies the filter
// func (c *ConditionPeerName) Apply(filter syscall.Handle, conditionIndex uint32) error {
// 	if err := preApply(c.Match, filter, conditionIndex, FwpmConditionPeerName); err != nil {
// 		return fmt.Errorf("condition pre-apply error: %w", err)
// 	}
// 	return FWPMFILTERSetConditionBlobString(filter, conditionIndex, c.DnsName)
// }

// ------------------------------------------------------------------------------------------------------

// ConditionIPLocalAddressV4 - new condition type implementation
type ConditionIPLocalAddressV4 struct {
	Match FwpMatchType
	IP    net.IP
	Mask  net.IP
}

// Apply applies the filter
func (c *ConditionIPLocalAddressV4) Apply(filter syscall.Handle, conditionIndex uint32) error {
	if err := preApply(c.Match, filter, conditionIndex, FwpmConditionIPLocalAddress); err != nil {
		return fmt.Errorf("condition pre-apply error: %w", err)
	}
	return FWPMFILTERSetConditionV4AddrMask(filter, conditionIndex, binary.BigEndian.Uint32(c.IP.To4()), binary.BigEndian.Uint32(c.Mask.To4()))
}

// ------------------------------------------------------------------------------------------------------

// ConditionIPLocalPort - new condition type implementation
type ConditionIPLocalPort struct {
	Match FwpMatchType
	Port  uint16
}

// Apply applies the filter
func (c *ConditionIPLocalPort) Apply(filter syscall.Handle, conditionIndex uint32) error {
	if err := preApply(c.Match, filter, conditionIndex, FwpmConditionIPLocalPort); err != nil {
		return fmt.Errorf("condition pre-apply error: %w", err)
	}
	return FWPMFILTERSetConditionUINT16(filter, conditionIndex, c.Port)
}

// ------------------------------------------------------------------------------------------------------

// ConditionIPRemotePort - new condition type implementation
type ConditionIPRemotePort struct {
	Match FwpMatchType
	Port  uint16
}

// Apply applies the filter
func (c *ConditionIPRemotePort) Apply(filter syscall.Handle, conditionIndex uint32) error {
	if err := preApply(c.Match, filter, conditionIndex, FwpmConditionIPRemotePort); err != nil {
		return fmt.Errorf("condition pre-apply error: %w", err)
	}
	return FWPMFILTERSetConditionUINT16(filter, conditionIndex, c.Port)
}

// ------------------------------------------------------------------------------------------------------

// ConditionIcmpType - new condition type implementation
type ConditionIcmpType struct {
	Match    FwpMatchType
	IcmpType uint16
}

// Apply applies the filter
func (c *ConditionIcmpType) Apply(filter syscall.Handle, conditionIndex uint32) error {
	if err := preApply(c.Match, filter, conditionIndex, FwpmConditionIcmpType); err != nil {
		return fmt.Errorf("condition pre-apply error: %w", err)
	}
	return FWPMFILTERSetConditionUINT16(filter, conditionIndex, c.IcmpType)
}

// ------------------------------------------------------------------------------------------------------

// ConditionIcmpType - new condition type implementation
type ConditionIcmpCode struct {
	Match    FwpMatchType
	IcmpCode uint16
}

// Apply applies the filter
func (c *ConditionIcmpCode) Apply(filter syscall.Handle, conditionIndex uint32) error {
	if err := preApply(c.Match, filter, conditionIndex, FwpmConditionIcmpCode); err != nil {
		return fmt.Errorf("condition pre-apply error: %w", err)
	}
	return FWPMFILTERSetConditionUINT16(filter, conditionIndex, c.IcmpCode)
}

// ------------------------------------------------------------------------------------------------------

// ConditionIPProtocol - new condition type implementation
type ConditionIPProtocol struct {
	Match      FwpMatchType
	IPProtocol uint8
}

// Apply applies the filter
func (c *ConditionIPProtocol) Apply(filter syscall.Handle, conditionIndex uint32) error {
	if err := preApply(c.Match, filter, conditionIndex, FwpmConditionIPProtocol); err != nil {
		return fmt.Errorf("condition pre-apply error: %w", err)
	}
	return FWPMFILTERSetConditionUINT8(filter, conditionIndex, c.IPProtocol)
}

// ------------------------------------------------------------------------------------------------------

// ConditionIPRemoteAddressV4 - new condition type implementation
type ConditionIPRemoteAddressV4 struct {
	Match FwpMatchType
	IP    net.IP
	Mask  net.IP
}

// Apply applies the filter
func (c *ConditionIPRemoteAddressV4) Apply(filter syscall.Handle, conditionIndex uint32) error {
	if err := preApply(c.Match, filter, conditionIndex, FwpmConditionIPRemoteAddress); err != nil {
		return fmt.Errorf("condition pre-apply error: %w", err)
	}
	return FWPMFILTERSetConditionV4AddrMask(filter, conditionIndex, binary.BigEndian.Uint32(c.IP.To4()), binary.BigEndian.Uint32(c.Mask.To4()))
}

// ------------------------------------------------------------------------------------------------------

// ConditionIPRemoteAddressV6 - new condition type implementation
type ConditionIPRemoteAddressV6 struct {
	Match     FwpMatchType
	IP        [16]byte
	PrefixLen byte
}

// Apply applies the filter
func (c *ConditionIPRemoteAddressV6) Apply(filter syscall.Handle, conditionIndex uint32) error {
	if err := preApply(c.Match, filter, conditionIndex, FwpmConditionIPRemoteAddress); err != nil {
		return fmt.Errorf("condition pre-apply error: %w", err)
	}
	return FWPMFILTERSetConditionV6AddrMask(filter, conditionIndex, c.IP, c.PrefixLen)
}

// ------------------------------------------------------------------------------------------------------

// ConditionIPLocalAddressV6 - new condition type implementation
type ConditionIPLocalAddressV6 struct {
	Match     FwpMatchType
	IP        [16]byte
	PrefixLen byte
}

// Apply applies the filter
func (c *ConditionIPLocalAddressV6) Apply(filter syscall.Handle, conditionIndex uint32) error {
	if err := preApply(c.Match, filter, conditionIndex, FwpmConditionIPLocalAddress); err != nil {
		return fmt.Errorf("condition pre-apply error: %w", err)
	}
	return FWPMFILTERSetConditionV6AddrMask(filter, conditionIndex, c.IP, c.PrefixLen)
}

// ------------------------------------------------------------------------------------------------------
