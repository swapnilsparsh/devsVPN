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
	"errors"
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ProviderInfo WFP provider information
type ProviderInfo struct {
	Key         syscall.GUID
	Name        string // DisplayData Name
	Description string // DisplayData Description

	Flags        uint32
	IsInstalled  bool
	IsPersistent bool

	ServiceName string // Optional name of the Windows service hosting the provider
}

// Provider - WFP provider
type Provider struct {
	key           syscall.GUID
	ddName        string // DisplayData Name
	ddDescription string // DisplayData Description
	isPersistence bool
}

// CreateProvider - create WFP provider
func CreateProvider(_key syscall.GUID, _ddName string, _ddDescription string, _isPersistence bool) Provider {
	return Provider{key: _key, ddName: _ddName, ddDescription: _ddDescription, isPersistence: _isPersistence}
}

// SubLayer - WFP SubLayer
type SubLayer struct {
	Key          syscall.GUID
	ProviderKey  syscall.GUID
	Name         string // DisplayData Name
	Description  string // DisplayData Description
	IsPersistent bool
	Weight       uint16
}

// CreateSubLayer - create WFP SubLayer
func CreateSubLayer(
	_key syscall.GUID,
	_providerKey syscall.GUID,
	_ddName string, _ddDescription string,
	_weight uint16,
	_isPersistence bool) SubLayer {
	return SubLayer{
		Key:          _key,
		ProviderKey:  _providerKey,
		Name:         _ddName,
		Description:  _ddDescription,
		IsPersistent: _isPersistence,
		Weight:       _weight}
}

func (sl SubLayer) String() string {
	return fmt.Sprintf("\tSublayer Key:\t%s\n\tProvider Key:\t%s\n\tName:\t\t%s\n\tDescription:\t%s\n\tPersistent:\t%t\n\tWeight:\t\t0x%04X",
		windows.GUID(sl.Key).String(), windows.GUID(sl.ProviderKey).String(), sl.Name, sl.Description, sl.IsPersistent, sl.Weight)
}

// Manager - helper to communicate WFP methods
type Manager struct {
	session syscall.Handle
	engine  syscall.Handle
}

func (m *Manager) isInitialized() bool {
	return m.engine != 0
}

// Initialize initialize WFP manager
func (m *Manager) Initialize() error {
	if m.isInitialized() {
		return nil // already initialized
	}

	var err error
	m.session, err = CreateWfpSessionObject(false)
	if err != nil {
		log.Error("failed to initialize firewall", err)
		return err
	}

	m.engine, err = WfpEngineOpen(m.session)
	if err != nil {
		log.Error("failed to initialize firewall", err)
		return err
	}

	return nil
}

// Uninitialize uninitialize WFP manager
func (m *Manager) Uninitialize() error {
	if m.session != 0 {
		if err := DeleteWfpSessionObject(m.session); err != nil {
			log.Error(err)
		}
	}
	m.session = 0

	if m.engine != 0 {
		if err := WfpEngineClose(m.engine); err != nil {
			log.Error(err)
		}
	}
	m.engine = 0
	return nil
}

// GetProviderInfo returns WFP provider info
/*
func (m *Manager) GetProviderInfo(providerKey syscall.GUID) (ProviderInfo, error) {
	if err := m.Initialize(); err != nil {
		return ProviderInfo{}, err
	}

	isInstalled, flags, err := WfpGetProviderFlags(m.engine, providerKey)
	if err != nil {
		return ProviderInfo{}, nil
	}

	return ProviderInfo{
			IsInstalled:  isInstalled,
			IsPersistent: bool((flags & FwpmProviderFlagPersistent) == FwpmProviderFlagPersistent)},
		nil
}
*/

// GetProviderInfo returns WFP provider info
func (m *Manager) GetProviderInfo(providerKey syscall.GUID) (found bool, provider ProviderInfo, err error) {
	if err := m.Initialize(); err != nil {
		return false, ProviderInfo{}, fmt.Errorf("failed to initialize manager: %w", err)
	}

	var fwpmProvider *FwpmProvider0

	found, err = FwpmProviderGetByKey0(windows.Handle(m.engine), ProviderID(providerKey), &fwpmProvider)
	defer FwpmFreeMemory0((*struct{})(unsafe.Pointer(&fwpmProvider)))

	if err != nil {
		err = log.ErrorE(fmt.Errorf("error calling FwpmProviderGetByKey0: %w", err), 0)
	} else if found {
		name := windows.UTF16PtrToString(fwpmProvider.DisplayData.Name)
		description := windows.UTF16PtrToString(fwpmProvider.DisplayData.Description)
		serviceName := windows.UTF16PtrToString(fwpmProvider.ServiceName)

		provider = ProviderInfo{
			Key:          syscall.GUID(fwpmProvider.ProviderKey),
			Name:         name,
			Description:  description,
			Flags:        uint32(fwpmProvider.Flags),
			IsInstalled:  true,
			IsPersistent: bool((uint32(fwpmProvider.Flags) & FwpmProviderFlagPersistent) == FwpmProviderFlagPersistent),
			ServiceName:  serviceName,
		}
	}

	return found, provider, err
}

// AddProvider adds WFP provider
func (m *Manager) AddProvider(prv Provider) (retErr error) {
	if len(prv.ddName) == 0 {
		return errors.New("unable to add WFP provider (DisplayData is empty)")
	}

	if err := m.Initialize(); err != nil {
		return fmt.Errorf("failed to initialize manager : %w", err)
	}

	prvHandle, err := FWPMPROVIDER0Create(prv.key)
	if err != nil {
		return fmt.Errorf("failed to create provider: %w", err)
	}

	defer func() {
		if prvHandle != syscall.Handle(0) {
			FWPMPROVIDER0Delete(prvHandle)
		}
	}()

	if prv.isPersistence {
		// return fmt.Errorf("AddProvider error - WFP (Windows Filtering Platform) persistence not supported")
		if err = FWPMPROVIDER0SetFlags(prvHandle, FwpmProviderFlagPersistent); err != nil {
			return fmt.Errorf("failed to set provider flags: %w", err)
		}
	}

	if err = FWPMPROVIDER0SetDisplayData(prvHandle, prv.ddName, prv.ddDescription); err != nil {
		return fmt.Errorf("failed to set provider display data: %w", err)
	}

	if err = WfpProviderAdd(m.engine, prvHandle); err != nil {
		return fmt.Errorf("failed to add provider: %w", err)
	}

	return nil
}

// DeleteProvider removes WFP provider
func (m *Manager) DeleteProvider(providerKey syscall.GUID) error {
	if !m.isInitialized() {
		return nil
	}

	return WfpProviderDelete(m.engine, providerKey)
}

// TransactionStart starts transaction
func (m *Manager) TransactionStart() error {
	if err := m.Initialize(); err != nil {
		return fmt.Errorf("failed to initialize manager: %w", err)
	}

	if err := WfpTransactionBegin(m.engine); err != nil {
		log.Error("failed to start WFP transaction", err)
		return err
	}
	return nil
}

// TransactionCommit commits transaction
func (m *Manager) TransactionCommit() error {
	if err := m.Initialize(); err != nil {
		return fmt.Errorf("failed to initialize manager: %w", err)
	}

	if err := WfpTransactionCommit(m.engine); err != nil {
		log.Error("failed to commit WFP transaction", err)
		return err
	}
	return nil
}

// TransactionAbort aborting transaction
func (m *Manager) TransactionAbort() error {
	if err := m.Initialize(); err != nil {
		return fmt.Errorf("failed to initialize manager: %w", err)
	}

	if err := WfpTransactionAbort(m.engine); err != nil {
		log.Error("failed to abort WFP transaction", err)
		return err
	}
	return nil
}

func (m *Manager) GetSubLayerByKey(sublayerKey syscall.GUID) (found bool, sublayer SubLayer, err error) {
	if err := m.Initialize(); err != nil {
		return false, SubLayer{}, fmt.Errorf("failed to initialize manager: %w", err)
	}

	var fwpmSublayer *FwpmSublayer0
	found, err = FwpmSubLayerGetByKey0(windows.Handle(m.engine), SublayerID(sublayerKey), &fwpmSublayer)
	defer FwpmFreeMemory0((*struct{})(unsafe.Pointer(&fwpmSublayer)))

	if err != nil {
		err = log.ErrorE(fmt.Errorf("error calling FwpmSubLayerGetByKey0: %w", err), 0)
	} else if found {
		name := windows.UTF16PtrToString(fwpmSublayer.DisplayData.Name)
		description := windows.UTF16PtrToString(fwpmSublayer.DisplayData.Description)

		var providerGuid syscall.GUID
		if fwpmSublayer.ProviderKey != nil { // FwpmSubLayerGetByKey0 can return nil instead of the pointer to provider key
			providerGuid = syscall.GUID(*fwpmSublayer.ProviderKey)
		} else {
			providerGuid = syscall.GUID{}
		}

		sublayer = CreateSubLayer(syscall.GUID(fwpmSublayer.SublayerKey),
			providerGuid,
			name,
			description,
			fwpmSublayer.Weight,
			(fwpmSublayer.Flags&fwpmSublayerFlagsPersistent) != 0)
	}

	return found, sublayer, err
}

func (m *Manager) FindSubLayerWithMaxWeight() (found bool, sublayerKey syscall.GUID, err error) {
	if err := m.Initialize(); err != nil {
		return false, syscall.GUID{}, fmt.Errorf("failed to initialize manager: %w", err)
	}

	return WfpFindSubLayerWithMaxWeight(m.engine)
}

// AddSubLayer adds WFP sublayer
func (m *Manager) AddSubLayer(sbl SubLayer) (retErr error) {
	if len(sbl.Name) == 0 {
		return errors.New("unable to add WFP sublayer (DisplayData is empty)")
	}

	if err := m.Initialize(); err != nil {
		return fmt.Errorf("failed to initialize manager: %w", err)
	}

	handler, err := FWPMSUBLAYER0Create(sbl.Key, sbl.Weight)
	if err != nil {
		return fmt.Errorf("failed to create sublayer: %w", err)
	}

	defer func() {
		if handler != syscall.Handle(0) {
			FWPMSUBLAYER0Delete(handler)
		}
	}()

	if err = FWPMSUBLAYER0SetProviderKey(handler, sbl.ProviderKey); err != nil {
		return fmt.Errorf("failed to set provider key: %w", err)
	}

	if sbl.IsPersistent {
		// return fmt.Errorf("AddSubLayer error - WFP (Windows Filtering Platform) persistence not supported")
		if err = FWPMSUBLAYER0SetFlags(handler, FwpmSublayerFlagPersistent); err != nil {
			return fmt.Errorf("failed to set sublayer flags: %w", err)
		}
	}

	if err = FWPMSUBLAYER0SetDisplayData(handler, sbl.Name, sbl.Description); err != nil {
		return fmt.Errorf("failed to set display data: %w", err)
	}

	return WfpSubLayerAdd(m.engine, handler)
}

// DeleteSubLayer removes WFP sublayer
func (m *Manager) DeleteSubLayer(sublayerKey syscall.GUID) (sublayerNotFound bool, err error) {
	if !m.isInitialized() {
		return false, errors.New("unable to delete WFP sublayer (engine not initialized)")
	}

	return WfpSubLayerDelete(m.engine, sublayerKey)
}

// AddFilter adds WFP filer
func (m *Manager) AddFilter(filter Filter) (filterID uint64, retErr error) {
	if len(filter.DisplayDataName) == 0 {
		return 0, errors.New("unable to add WFP filer (DisplayData is empty)")
	}

	if err := m.Initialize(); err != nil {
		return 0, fmt.Errorf("failed to initialize manager: %w", err)
	}

	handler, err := FWPMFILTERCreate(filter.Key, filter.KeyLayer, filter.KeySublayer, filter.Weight, filter.Flags)
	if err != nil {
		return 0, fmt.Errorf("failed to create filter: %w", err)
	}

	defer func() {
		if handler != syscall.Handle(0) {
			FWPMFILTERDelete(handler)
		}
	}()

	if err = FWPMFILTERSetProviderKey(handler, filter.KeyProvider); err != nil {
		return 0, fmt.Errorf("failed to set provider key: %w", err)
	}

	if err = FWPMFILTERSetDisplayData(handler, filter.DisplayDataName, filter.DisplayDataDescription); err != nil {
		return 0, fmt.Errorf("failed to set display data: %w", err)
	}

	if err = FWPMFILTERSetAction(handler, filter.Action); err != nil {
		return 0, fmt.Errorf("failed to set filter action: %w", err)
	}

	if err = FWPMFILTERAllocateConditions(handler, uint32(len(filter.Conditions))); err != nil {
		return 0, fmt.Errorf("failed to allocate filter conditions: %w", err)
	}

	for index, c := range filter.Conditions {
		if err = c.Apply(handler, uint32(index)); err != nil {
			return 0, fmt.Errorf("failed to apply filter condition : %w", err)
		}
	}

	id, e := WfpFilterAdd(m.engine, handler)
	if e != nil {
		return id, e
	}

	return id, nil
}

// DeleteFilterByID removes WFP filter
func (m *Manager) DeleteFilterByID(filterID uint64) error {
	if !m.isInitialized() {
		return errors.New("unable to delete WFP filter (engine not initialized)")
	}

	if filterID == 0 {
		return errors.New("unable to delete WFP filter (filter ID not defined)")
	}

	return WfpFilterDeleteByID(m.engine, filterID)
}

// DeleteFilterByProviderKey removes WFP filter by provider key
func (m *Manager) DeleteFilterByProviderKey(providerKey syscall.GUID, layerKey syscall.GUID) error {
	if !m.isInitialized() {
		return errors.New("unable to delete WFP filter (engine not initialized)")
	}

	return WfpFiltersDeleteByProviderKey(m.engine, providerKey, layerKey)
}
