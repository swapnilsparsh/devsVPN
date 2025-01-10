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
	"encoding/json"
	"fmt"
	"net"

	"github.com/swapnilsparsh/devsVPN/daemon/helpers"
	"github.com/swapnilsparsh/devsVPN/daemon/protocol/types"
)

type ICommandBase interface {
	Init(name string, idx int)
	Name() string
	Index() int
	LogExtraInfo() string
}

type IResponseBase interface {
	GetError() string
}

// Send initializes and sends command to a client
// Note: this function modifies cmd object by adding command name and index
func Send(conn net.Conn, cmd ICommandBase, idx int) error {
	if conn == nil {
		return fmt.Errorf("connection is nil")
	}
	cmd.Init(types.GetTypeName(cmd), idx)
	bytesToSend, err := json.Marshal(cmd)
	if err != nil {
		return fmt.Errorf("failed to serialise command: %w", err)
	}
	if bytesToSend == nil {
		return fmt.Errorf("data is nil")
	}
	bytesToSend = append(bytesToSend, byte('\n'))
	if _, err := conn.Write(bytesToSend); err != nil {
		return err
	}
	return nil
}

func SendCustom(conn net.Conn, data, cmdName string, idx int) error {
	bytesToSend, err := json.Marshal(map[string]string{
		"Data":    data,
		"Command": cmdName,
		"Idx":     string(idx),
	})

	if err != nil {
		return fmt.Errorf("failed to serialise command: %w", err)
	}
	if bytesToSend == nil {
		return fmt.Errorf("data is nil")
	}
	bytesToSend = append(bytesToSend, byte('\n'))
	if _, err := conn.Write(bytesToSend); err != nil {
		return err
	}
	return nil
}

func (p *Protocol) notifyClients(cmd ICommandBase) {
	p._connectionsMutex.RLock()
	defer p._connectionsMutex.RUnlock()

	for conn := range p._connections {
		p.sendResponse(conn, cmd, 0)
	}
}

func (p *Protocol) customNotifyClients(data interface{}, cmd string, idx int) {
	p._connectionsMutex.RLock()
	defer p._connectionsMutex.RUnlock()

	jsonData, err := json.Marshal(data)
	if err != nil {
		log.Error(err)
		return
	}

	for conn, connInfo := range p._connections {
		if connInfo.Type == types.ClientCli {
			continue // don't send rx/tx stats and handshake timestamp to CLI clients, as they hang on unexpected response
		}
		SendCustom(conn, string(jsonData), cmd, idx)
	}
}

func (p *Protocol) sendError(conn net.Conn, errorText string, cmdIdx int) {
	log.Error(errorText)
	p.sendResponse(conn, &types.ErrorResp{ErrorMessage: errorText}, cmdIdx)
}

func (p *Protocol) sendErrorResponse(conn net.Conn, request types.RequestBase, err error) {
	log.Error(fmt.Errorf("%sError processing request '%s': %w", p.connLogID(conn), request.Command, err))
	p.sendResponse(conn, &types.ErrorResp{ErrorMessage: helpers.CapitalizeFirstLetter(err.Error())}, request.Idx)
}

func (p *Protocol) sendResponse(conn net.Conn, cmd ICommandBase, idx int) (retErr error) {
	if err := Send(conn, cmd, idx); err != nil {
		return fmt.Errorf("%sfailed to send command: %w", p.connLogID(conn), err)
	}
	log.Info(fmt.Sprintf("[-->] %s", p.connLogID(conn)), cmd.Name(), fmt.Sprintf(" [%d]", cmd.Index()), " ", cmd.LogExtraInfo())
	return nil
}
