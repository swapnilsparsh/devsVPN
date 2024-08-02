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

	"github.com/swapnilsparsh/devsVPN/daemon/splittun"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// structure contains properties required for for Linux implementation
type osSpecificProperties struct {
	stopChanMutex sync.Mutex // protects stopChan
	stopChan      chan bool

	routeUpdateChan        chan netlink.RouteUpdate
	routeSubscribeDoneChan chan struct{}
}

func (d *Detector) isRoutingChanged() (bool, error) {
	// Not implemented, we don't have a protected interface in MVP 1.0
	return false, nil
}

func (d *Detector) doStart() {
	log.Info("Route change detector started")

	d.props.stopChanMutex.Lock()
	d.props.stopChan = make(chan bool)
	d.props.stopChanMutex.Unlock()

	d.props.routeUpdateChan = make(chan netlink.RouteUpdate)
	d.props.routeSubscribeDoneChan = make(chan struct{})

	defer func() {
		close(d.props.routeSubscribeDoneChan) // this will also close routeUpdateChan
		d.props.routeSubscribeDoneChan = nil
		d.props.routeUpdateChan = nil

		d.props.stopChanMutex.Lock()
		close(d.props.stopChan)
		d.props.stopChan = nil
		d.props.stopChanMutex.Unlock()

		log.Info("Route change detector stopped")
	}()

	if err := netlink.RouteSubscribe(d.props.routeUpdateChan, d.props.routeSubscribeDoneChan); err != nil {
		log.Error(fmt.Errorf("error netlink.RouteSubscribe(): %w", err))
		return
	}

	for {
		select {
		case <-d.props.stopChan:
			return
		case routeUpdate := <-d.props.routeUpdateChan: // handle only new routes with nil or 0.0.0.0 destinations
			if routeUpdate.Type == unix.RTM_NEWROUTE && (routeUpdate.Dst == nil || splittun.DefaultRoutesByIpFamily[splittun.AF_INET].IP.Equal(routeUpdate.Dst.IP)) {
				d.routingChangeDetected()
			}
		}
	}
}

func (d *Detector) doStop() {
	d.props.stopChanMutex.Lock()
	if d.props.stopChan != nil {
		d.props.stopChan <- true
	}
	d.props.stopChanMutex.Unlock()
}
