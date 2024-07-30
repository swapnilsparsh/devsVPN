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

package netchange

import (
	"fmt"
	"sync"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// structure contains properties required for for Linux implementation
type osSpecificProperties struct {
	routeUpdateChanMutex sync.Mutex // protects routeUpdateChan
	routeUpdateChan      chan netlink.RouteUpdate

	routeSubscribeDoneChan chan struct{}
}

func (d *Detector) isRoutingChanged() (bool, error) {
	// Not implemented, we don't have a protected interface in MVP 1.0
	return false, nil
}

func (d *Detector) doStart() {
	log.Info("Route change detector started")
	d.props.routeUpdateChanMutex.Lock() // initialization critical section - we don't want any race conditions
	d.props.routeUpdateChan = make(chan netlink.RouteUpdate)
	d.props.routeUpdateChanMutex.Unlock()

	d.props.routeSubscribeDoneChan = make(chan struct{})

	defer func() {
		close(d.props.routeSubscribeDoneChan)

		d.props.routeUpdateChanMutex.Lock()
		close(d.props.routeUpdateChan)
		d.props.routeUpdateChan = nil
		d.props.routeUpdateChanMutex.Unlock()

		log.Info("Route change detector stopped")
	}()

	if err := netlink.RouteSubscribe(d.props.routeUpdateChan, d.props.routeSubscribeDoneChan); err != nil {
		log.Error(fmt.Errorf("error netlink.RouteSubscribe(): %w", err))
		return
	}

	for {
		routeUpdate := <-d.props.routeUpdateChan
		if routeUpdate.Type == unix.RTM_F_NOTIFY { // stop signal
			return
		}
		d.routingChangeDetected()
	}
}

func (d *Detector) doStop() { // Legitimate types returned on route changes are RTM_NEWROUTE or RTM_DELROUTE. Send an out-of-band message to signal stop.
	d.props.routeUpdateChanMutex.Lock()
	if d.props.routeUpdateChan != nil {
		d.props.routeUpdateChan <- netlink.RouteUpdate{Type: unix.RTM_F_NOTIFY}
	}
	d.props.routeUpdateChanMutex.Unlock()
}
