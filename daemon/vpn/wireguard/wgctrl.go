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

package wireguard

import (
	"fmt"
	"math"
	"time"

	"github.com/swapnilsparsh/devsVPN/daemon/protocol"
	"golang.zx2c4.com/wireguard/wgctrl"
)

var byteUnits = []string{"Bytes", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB"}

func formatBytes(bytes int64) string {
	if bytes == 0 {
		return "0 Bytes"
	}

	magnitude := int(math.Floor(math.Log(float64(bytes)) / math.Log(1024)))
	value := float64(bytes) / math.Pow(1024, float64(magnitude))

	return fmt.Sprintf("%.2f %s", value, byteUnits[magnitude])
}

// WaitForMultipleHandshakes waits for a handshake during 'timeout' time.
// It returns channel that will be closed when handshake detected. In case of error, channel will contain error.
// if stopTriggers is defined and at least one of it's elements == true: function stops and channel closes.
func WaitForWireguardMultipleHandshakesChan(tunnelName string, stopTriggers []*bool, logFunc func(string), statisticsCallbacks protocol.StatsCallbacks) <-chan error {
	retChan := make(chan error, 1)

	go func() (retError error) {
		defer func() {
			if r := recover(); r != nil {
				if err, ok := r.(error); ok {
					retChan <- fmt.Errorf("crash (recovered): %w", err)
				}
			} else {
				retChan <- retError
			}
			close(retChan)
		}()

		logTimeout := time.Second * 5
		nextTimeToLog := time.Now().Add(logTimeout)

		client, err := wgctrl.New()
		if err != nil {
			return fmt.Errorf("failed to check handshake info: %w", err)
		}
		defer client.Close()

		previousHandshakeTimes := make(map[string]time.Time) // Track handshake times for each peer

		for {
			time.Sleep(time.Millisecond * 50)

			for _, isStop := range stopTriggers {
				if isStop != nil && *isStop {
					return nil // stop requested (probably, disconnect requested or already disconnected)
				}
			}

			dev, err := client.Device(tunnelName)
			if err != nil {
				return fmt.Errorf("failed to check handshake info for '%s': %w", tunnelName, err)
			}

			for _, peer := range dev.Peers {

				currentRxBytes := int64(peer.ReceiveBytes)
				currentTxBytes := int64(peer.TransmitBytes)

				// Convert bytes to a readable format
				received := formatBytes(currentRxBytes)
				sent := formatBytes(currentTxBytes)

				statisticsCallbacks.OnTransferDataCallback(sent, received)

				// Log the transfer speed
				if logFunc != nil {
					logFunc(fmt.Sprintf("Total Data received: %s, Total Data sent: %s", received, sent))
				}

				if !peer.LastHandshakeTime.IsZero() {
					previousTime, known := previousHandshakeTimes[peer.PublicKey.String()]
					if !known || !peer.LastHandshakeTime.Equal(previousTime) {
						if logFunc != nil {
							logFunc(fmt.Sprintf("New handshake detected for peer %s at %s", peer.PublicKey, peer.LastHandshakeTime))
						}
						statisticsCallbacks.OnHandshakeCallback(peer.LastHandshakeTime.String())
						previousHandshakeTimes[peer.PublicKey.String()] = peer.LastHandshakeTime

						// Non-blocking send to retChan
						select {
						case retChan <- nil:
						default:
							// Avoid blocking if no one is receiving
						}
					}
				}
			}

			if logFunc != nil && time.Now().After(nextTimeToLog) {
				logTimeout = logTimeout * 2
				if logTimeout > time.Minute {
					logTimeout = time.Minute
				}
				logFunc("Waiting for handshake ...")
				nextTimeToLog = time.Now().Add(logTimeout)
			}
		}
	}()
	return retChan
}

func WaitForDisconnectChan(tunnelName string, isStop []*bool) <-chan error {
	return waitForWgInterfaceChan(tunnelName, true, isStop)
}
func WaitForConnectChan(tunnelName string, isStop []*bool) <-chan error {
	return waitForWgInterfaceChan(tunnelName, false, isStop)
}

// if isStopArray is defined and at lease one of it's elements == true: function stops and channel closes
func waitForWgInterfaceChan(tunnelName string, isWaitForDisconnect bool, isStopArray []*bool) <-chan error {
	retChan := make(chan error, 1)

	go func() (retError error) {
		defer func() {
			if r := recover(); r != nil {
				if err, ok := r.(error); ok {
					retChan <- fmt.Errorf("crash (recovered): %w", err)
				}
			} else {
				retChan <- retError
			}
			close(retChan)
		}()

		client, err := wgctrl.New()
		if err != nil {
			return err
		}
		defer client.Close()

		for ; ; time.Sleep(time.Millisecond * 50) {
			_, err := client.Device(tunnelName)
			if isWaitForDisconnect && err != nil {
				break // waiting for Disconnect: return when error obtaining WG tunnel info
			} else if !isWaitForDisconnect && err == nil {
				break // waiting for Connect: return when NO error obtaining WG tunnel info
			}

			for _, isStop := range isStopArray {
				if isStop != nil && *isStop {
					return nil
				}
			}

		}
		return nil
	}()

	return retChan
}
