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

package protocol

import (
	"sync"

	api_types "github.com/swapnilsparsh/devsVPN/daemon/api/types"
	"github.com/swapnilsparsh/devsVPN/daemon/protocol/types"
	"github.com/swapnilsparsh/devsVPN/daemon/service/preferences"
	"github.com/swapnilsparsh/devsVPN/daemon/wifiNotifier"
)

// OnServiceSessionChanged - SessionChanged handler
func (p *Protocol) OnServiceSessionChanged() {
	// send back Hello message with account session info
	helloResp := p.createHelloResponse()
	p.notifyClients(helloResp)
}

// OnSessionStatus - handler of session/account status info. Notifying clients.
func (p *Protocol) OnSessionStatus(sessionToken string, sessionData preferences.SessionMutableData) {
	if len(sessionToken) == 0 {
		return
	}

	p.notifyClients(&types.SessionStatusResp{
		SessionToken: sessionToken,
		Account:      sessionData.Account,
		DeviceName:   sessionData.DeviceName,
	})
}

var OnKillSwitchStateChangedMutex sync.Mutex

// OnKillSwitchStateChanged - Firewall change handler. Single-instance.
func (p *Protocol) OnKillSwitchStateChanged() {
	OnKillSwitchStateChangedMutex.Lock() // single instance.
	defer OnKillSwitchStateChangedMutex.Unlock()

	if p._service == nil {
		return
	}

	// notify all clients about KillSwitch status
	if status, err := p._service.KillSwitchState(); err != nil {
		log.ErrorFE("error in p._service.KillSwitchState(): %w", err)
	} else {
		p.notifyClients(&types.KillSwitchStatusResp{KillSwitchStatus: status})
	}
}

// OnWiFiChanged - handler of WiFi status change. Notifying clients.
func (p *Protocol) OnWiFiChanged(info wifiNotifier.WifiInfo, err error) {
	msg := &types.WiFiCurrentNetworkResp{
		SSID:              info.SSID,
		IsInsecureNetwork: info.IsInsecure,
	}
	if err != nil {
		msg.Error = err.Error()
	}
	p.notifyClients(msg)
}

func (p *Protocol) OnTransferData(sent string, received string) {
	msg := types.TransferredDataResp{
		SentData:     sent,
		ReceivedData: received,
	}
	p.customNotifyClients(msg, "TransferredDataResp", 0)
}

func (p *Protocol) OnHandshake(handshakeTime string) {
	msg := types.HandshakeResp{
		HandshakeTime: handshakeTime,
	}
	p.customNotifyClients(msg, "HandshakeResp", 0)
}

// OnPingStatus - servers ping status
func (p *Protocol) OnPingStatus(retMap map[string]int) {
	var results []types.PingResultType
	for k, v := range retMap {
		results = append(results, types.PingResultType{Host: k, Ping: v})
	}
	p.notifyClients(&types.PingServersResp{PingResults: results})
}

func (p *Protocol) OnServersUpdated(serv *api_types.ServersInfoResponse) {
	if serv == nil {
		return
	}
	p.notifyClients(&types.ServerListResp{VpnServers: *serv})
}

func (p *Protocol) OnSplitTunnelStatusChanged() {
	if p._service == nil {
		return
	}
	status, err := p._service.SplitTunnelling_GetStatus()
	if err != nil {
		return
	}
	p.notifyClients(&status)
}
