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

package main

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/swapnilsparsh/devsVPN/daemon/api"
	"github.com/swapnilsparsh/devsVPN/daemon/helpers"
	"github.com/swapnilsparsh/devsVPN/daemon/logger"
	"github.com/swapnilsparsh/devsVPN/daemon/netchange"
	"github.com/swapnilsparsh/devsVPN/daemon/protocol"
	"github.com/swapnilsparsh/devsVPN/daemon/service"
	"github.com/swapnilsparsh/devsVPN/daemon/service/firewall"
	"github.com/swapnilsparsh/devsVPN/daemon/service/platform"
	"github.com/swapnilsparsh/devsVPN/daemon/service/preferences"
	"github.com/swapnilsparsh/devsVPN/daemon/service/wgkeys"
	"github.com/swapnilsparsh/devsVPN/daemon/version"
)

var log *logger.Logger
var activeProtocol IProtocol

// systemLog - if channel initialized, service will write there messages for system log.
//
//	Channel have to be initialized in platform-specific implementation of 'main' package (e.g. doPrepareToRun()).
//	Messages receiver (processing messages from the channel) also have to be implemented for each platform separately.
var systemLog chan service.SystemLogMessage

func init() {
	log = logger.NewLogger("launch")
}

// IProtocol - interface of communication protocol with privateLINE UI or CLI application
type IProtocol interface {
	Start(secret uint64, startedOnPort chan<- int, serv protocol.Service) error
	Stop()
}

// Launch -  initialize and start service
func Launch() {
	warnings, errors, logInfo := platform.Init()
	logger.Init(platform.LogFile())

	// Logging enabled from command line argument ('-logging').
	// Logging can be enabled from command line or from previously saved daemon preferences
	//
	// Vlad - enabling logging from get-go for the time being
	isLoggingEnabledArgument := true
	// Cleanup requested ('-cleanup'). Do not start server.
	isCleanupArgument := false

	// Checking command line arguments
	for _, arg := range os.Args {
		arg = strings.ToLower(arg)
		// if arg == "-logging" || arg == "--logging" {
		// 	isLoggingEnabledArgument = true
		// }
		if arg == "-cleanup" || arg == "--cleanup" {
			// Cleanup requested.
			// IMPORTANT! This operation must be executed ONLY when no any daemon instances running!
			isLoggingEnabledArgument = true
			isCleanupArgument = true
		}
	}

	if isLoggingEnabledArgument {
		logger.Enable(true)
		logger.Info("Logging enabled at build time")
		// logger.Info("Logging enabled (forced by command line argument)")
	} else {
		// initialize logging according to service preferences
		var prefs preferences.Preferences
		if err := prefs.LoadPreferences(); err == nil {
			logger.Enable(prefs.IsLogging)
		}
	}

	// Log full version
	logger.Info("version:" + version.GetFullVersion())

	// Now that logger is initialized, set up panic handler - ensure we log panic message (at least on this goroutine) before exiting on it
	defer func() {
		if r := recover(); r != nil {
			logger.Error(fmt.Errorf("PANIC at runtime: %v", r))
			logger.Error(string(debug.Stack()))
			if err, ok := r.(error); ok {
				logger.ErrorTrace(err)
			}
			os.Exit(1)
		}
	}()

	if isCleanupArgument {
		// Cleanup requested: just do logout, disable firewall and exit.
		// This can happen on Linux Snap package uninstall (out from 'remove' hook)
		os.Exit(doCleanup())
		return
	}

	// Logging platform initialization info messages
	for _, platformInitLogItem := range logInfo {
		logger.Info(fmt.Sprintf("INIT: %s", platformInitLogItem))
	}
	// Logging platform initialization warnings
	for _, w := range warnings {
		logger.Warning(w)
	}
	// Logging platform initialization errors
	if len(errors) > 0 {
		for _, e := range errors {
			logger.Error(e)
		}

		logger.Info("Daemon failed to start due to initialization errors")
		os.Exit(1)
		return
	}

	defer func() {
		doBeforeStop() // OS-specific steps required before shutdown
		log.Info(helpers.ServiceName + " daemon stopped.")
		doStopped() // OS-specific service finalizer
	}()

	tzName, tzOffsetSec := time.Now().Zone()

	log.Info(fmt.Sprintf("Starting %s daemon [%s,%s] [timezone: %s %d (%dh)] [pid: %d; ppid: %d; arch: %dbit]",
		helpers.ServiceName, runtime.GOOS, runtime.GOARCH,
		tzName, tzOffsetSec, tzOffsetSec/(60*60),
		os.Getpid(), os.Getppid(), strconv.IntSize))

	log.Info(fmt.Sprintf("args: %s", os.Args))

	if !doCheckIsAdmin() {
		logger.Warning("------------------------------------")
		logger.Warning("!!! NOT A PRIVILEGED USER !!!")
		logger.Warning("Please, ensure you are running an application with privileged rights.")
		logger.Warning("Otherwise, application will not work correctly.")
		logger.Warning("------------------------------------")
	}

	var secret uint64
	if err := binary.Read(rand.Reader, binary.BigEndian, &secret); err != nil {
		log.Panic(fmt.Errorf("failed to generate secret: %w", err))
	}

	// obtain (over callback channel) a service listening port
	startedOnPortChan := make(chan int, 1)
	go func() {
		// waiting for port number info
		openedPort := <-startedOnPortChan

		// save port info into a file (UI/CLI clients is able to read it)
		file, err := os.Create(platform.ServicePortFile())
		if err != nil {
			logger.Panic(err.Error())
		}
		defer file.Close()
		if _, err := file.WriteString(fmt.Sprintf("%d:%x", openedPort, secret)); err != nil {
			log.Error(fmt.Errorf("failed to write port info into file: %w", err))
		}

		// inform OS-specific implementation about listener port
		doStartedOnPort(openedPort, secret)
	}()

	defer os.Remove(platform.ServicePortFile())

	// perform OS-specific preparations (if necessary)
	if err := doPrepareToRun(); err != nil {
		logger.Panic(err.Error())
	}

	// run service
	launchService(secret, startedOnPortChan)
}

// Stop the service
func Stop() {
	p := activeProtocol
	if p != nil {
		p.Stop()
	}
}

// Logout can be requested by Linux Snap package 'remove' hook (using command line argument)
// IMPORTANT! This operation must be executed ONLY when no any daemon instances running!
func doCleanup() (osExitCode int) {
	log = logger.NewLogger("clean!")
	log.Info("disabled")
	return 0

	f := func() (retErr error) {
		if !doCheckIsAdmin() {
			return fmt.Errorf("not privileged environment")
		}
		var prefs preferences.Preferences
		if err := prefs.LoadPreferences(); err != nil {
			return err
		}

		// Try to logout
		session := prefs.Session
		if !session.IsLoggedIn() {
			log.Info("Not logged in")
		} else {
			if apiObj, err := api.CreateAPI(); err != nil { // API object
				retErr = log.ErrorE(fmt.Errorf("api.CreateAPI() failed: %w", err), 0)
			} else {
				log.Info("Logging out ...")
				if err = apiObj.SessionDelete(session.Session, prefs.Session.WGPublicKey); err != nil {
					retErr = log.ErrorE(fmt.Errorf("apiObj.SessionDelete() failed: %w", err), 0)
				} else {
					log.Info("Logging out: done")
				}
			}
		}

		// Disable firewall (if enabled) - must be done after logging out, because firewall rules assure we have access to api.privateline.io
		var fwErr error
		fwEnabled, err := firewall.GetEnabled()
		if err != nil {
			fwErr = log.ErrorFE("firewall.GetEnabled() failed: %w", err)
		} else if fwEnabled {
			log.Info("Disabling firewall ...")
			if err = firewall.SetEnabled(false); err != nil {
				fwErr = log.ErrorE(fmt.Errorf("firewall.SetEnabled() failed: %w", err), 0)
			} else {
				log.Info("Firewall disabled")
			}
		}

		// Clean-up our firewall registration, delete all firewall objects
		log.Info("Cleaning up firewall registration ...")
		if err = firewall.CleanupRegistration(); err != nil {
			fwErr = log.ErrorE(fmt.Errorf("firewall.CleanupRegistration() failed: %w", err), 0)
		} else {
			log.Info("Firewall registration cleaned up")
		}

		if retErr != nil {
			return retErr
		} else {
			return fwErr
		}
	}

	if err := f(); err != nil {
		log.Error(err)
		return 2
	}

	return 0
}

// initialize and start service
func launchService(secret uint64, startedOnPort chan<- int) {
	// API object
	apiObj, err := api.CreateAPI()
	if err != nil {
		log.Panic("API object initialization failed: ", err)
	}

	// servers updater
	updater, err := service.CreateServersUpdater(apiObj)
	if err != nil {
		log.Panic("ServersUpdater initialization failed: ", err)
	}

	// network change detector
	netDetector := netchange.Create()

	// WireGuard keys manager
	wgKeysMgr := wgkeys.CreateKeysManager(apiObj, platform.WgToolBinaryPath())

	// communication protocol
	protocol, err := protocol.CreateProtocol()
	if err != nil {
		log.Panic("Protocol object initialization failed: ", err)
	}

	// save protocol (to be able to stop it)
	activeProtocol = protocol

	// initialize service
	serv, err := service.CreateService(protocol,
		apiObj,
		updater,
		netDetector,
		wgKeysMgr,
		serviceEventsChan,
		systemLog)
	if err != nil {
		log.Panic("Failed to initialize service:", err)
	}

	// handle interrupt signals
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGQUIT)
	go func() {
		s := <-sigc
		log.Warning(fmt.Sprintf("SIGNAL received: '%v'. STOPPING DAEMON...", s))
		protocol.Stop()
	}()

	// start receiving requests from client (synchronous)
	if err := protocol.Start(secret, startedOnPort, serv); err != nil {
		log.Error("Protocol stopped with error:", err)
	}
}
