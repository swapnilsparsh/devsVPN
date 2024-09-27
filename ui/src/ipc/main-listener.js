//
//  UI for IVPN Client Desktop
//  https://github.com/swapnilsparsh/devsVPN
//
//  Created by Stelnykovych Alexandr.
//  Copyright (c) 2023 IVPN Limited.
//
//  This file is part of the UI for IVPN Client Desktop.
//
//  The UI for IVPN Client Desktop is free software: you can redistribute it and/or
//  modify it under the terms of the GNU General Public License as published by the Free
//  Software Foundation, either version 3 of the License, or (at your option) any later version.
//
//  The UI for IVPN Client Desktop is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
//  or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
//  details.
//
//  You should have received a copy of the GNU General Public License
//  along with the UI for IVPN Client Desktop. If not, see <https://www.gnu.org/licenses/>.
//

import {
  SentryIsAbleToUse,
  SentrySendDiagnosticReport,
} from "@/sentry/sentry.js";

import { ipcMain, nativeTheme, dialog, app, shell, BrowserWindow, session } from "electron";
import path from "path";
const { URL, URLSearchParams } = require('url');

import { Platform } from "@/platform/platform";
import { GetLinuxSnapEnvVars } from "@/helpers/main_platform";

import {
  CancelDownload,
  CheckUpdates,
  Install,
  IsAbleToCheckUpdate,
  Upgrade,
} from "@/app-updater";
import { AutoLaunchIsEnabled, AutoLaunchSet } from "@/auto-launch";
import config from "@/config";
import store from "@/store";
import client from "../daemon-client";

import os from "os";

// info: this event is processing in 'background.js'
//ipcMain.handle("renderer-request-connect-to-daemon", async () => {
//  return await client.ConnectToDaemon();
//});

ipcMain.handle("renderer-request-refresh-storage", async () => {
  // function using to re-apply all mutations
  // This is required to send to renderer processes current storage state
  store.commit("replaceState", store.state);
});

ipcMain.handle(
  "renderer-request-login",
  async (
    event,
    email,
    password
    // force, captchaID, captcha, confirmation2FA
  ) => {
    return await client.Login(
      email,
      password
      // force,
      // captchaID,
      // captcha,
      // confirmation2FA
    );
  }
);

ipcMain.handle("renderer-request-AccountInfo", async () => {
  return await client.AccountInfo();
});

ipcMain.handle(
  "renderer-request-logout",
  async (
    event,
    needToResetSettings,
    needToDisableFirewall,
    isCanDeleteSessionLocally
  ) => {
    return await client.Logout(
      needToResetSettings,
      needToDisableFirewall,
      isCanDeleteSessionLocally
    );
  }
);

ipcMain.handle("renderer-request-session-status", async () => {
  return await client.SessionStatus();
});

ipcMain.handle("renderer-request-ping-servers", async () => {
  return client.PingServers();
});

ipcMain.handle("renderer-request-update-servers-request", async () => {
  return client.ServersUpdateRequest();
});

ipcMain.handle("renderer-request-connect", async () => {
  return await client.Connect();
});
ipcMain.handle("renderer-request-disconnect", async () => {
  return await client.Disconnect();
});

ipcMain.handle(
  "renderer-request-pause-connection",
  async (event, pauseSeconds) => {
    return await client.PauseConnection(pauseSeconds);
  }
);
ipcMain.handle("renderer-request-resume-connection", async () => {
  return await client.ResumeConnection();
});

ipcMain.handle("renderer-request-firewall", async (event, enable) => {
  return await client.EnableFirewall(enable);
});
ipcMain.handle(
  "renderer-request-KillSwitchSetAllowApiServers",
  async (event, enable) => {
    return await client.KillSwitchSetAllowApiServers(enable);
  }
);
ipcMain.handle(
  "renderer-request-KillSwitchSetAllowLANMulticast",
  async (event, enable) => {
    return await client.KillSwitchSetAllowLANMulticast(enable);
  }
);
ipcMain.handle(
  "renderer-request-KillSwitchSetAllowLAN",
  async (event, enable) => {
    return await client.KillSwitchSetAllowLAN(enable);
  }
);
ipcMain.handle(
  "renderer-request-KillSwitchSetIsPersistent",
  async (event, enable) => {
    return await client.KillSwitchSetIsPersistent(enable);
  }
);

ipcMain.handle(
  "renderer-request-KillSwitchSetUserExceptions",
  async (event, userExceptions) => {
    return await client.KillSwitchSetUserExceptions(userExceptions);
  }
);

ipcMain.handle("renderer-request-SplitTunnelGetStatus", async () => {
  return await client.SplitTunnelGetStatus();
});
ipcMain.handle(
  "renderer-request-SplitTunnelSetConfig",
  async (event, enabled, inversed, isAnyDns, allowWhenNoVpn, doReset) => {
    return await client.SplitTunnelSetConfig(
      enabled,
      inversed,
      isAnyDns,
      allowWhenNoVpn,
      doReset
    );
  }
);
ipcMain.handle(
  "renderer-request-SplitTunnelRemoveApp",
  async (event, pid, execCmd) => {
    return await client.SplitTunnelRemoveApp(pid, execCmd);
  }
);

ipcMain.handle("renderer-request-ProfileData", async () => {
  return await client.ProfileData();
});

ipcMain.handle("renderer-request-SubscriptionData", async () => {
  return await client.SubscriptionData();
});

ipcMain.handle("renderer-request-GetInstalledApps", async () => {
  return await client.GetInstalledApps();
});

ipcMain.handle("renderer-request-SetUserPrefs", async (event, userPrefs) => {
  return await client.SetUserPrefs(userPrefs);
});

ipcMain.handle(
  "renderer-request-SetAutoconnectOnLaunch",
  async (event, isEnabled, isApplicableByDaemonInBackground) => {
    return await client.SetAutoconnectOnLaunch(
      isEnabled,
      isApplicableByDaemonInBackground
    );
  }
);
ipcMain.handle("renderer-request-set-logging", async (event, enable) => {
  return await client.SetLogging(enable);
});

ipcMain.handle("renderer-request-set-dns", async () => {
  return await client.SetDNS();
});

ipcMain.handle("renderer-request-RequestDnsPredefinedConfigs", async () => {
  return await client.RequestDnsPredefinedConfigs();
});

ipcMain.handle("renderer-request-geolookup", async () => {
  return await client.GeoLookup();
});

ipcMain.handle("renderer-request-wg-regenerate-keys", async () => {
  return await client.WgRegenerateKeys();
});

ipcMain.handle(
  "renderer-request-wg-set-keys-rotation-interval",
  async (event, intervalSec) => {
    return await client.WgSetKeysRotationInterval(intervalSec);
  }
);

ipcMain.handle(
  "renderer-request-wifi-set-settings",
  async (event, wifiParams) => {
    return await client.SetWiFiSettings(wifiParams);
  }
);

ipcMain.handle("renderer-request-wifi-get-available-networks", async () => {
  return await client.GetWiFiAvailableNetworks();
});

// Diagnostic reports
ipcMain.on("renderer-request-is-can-send-diagnostic-logs", (event) => {
  event.returnValue = SentryIsAbleToUse();
});
ipcMain.handle("renderer-request-get-diagnostic-logs", async () => {
  let data = await client.GetDiagnosticLogs();
  if (data == null) data = {};

  const s = store.state;

  //  version
  let daemonVer = s.daemonVersion;
  if (!daemonVer) daemonVer = "UNKNOWN";
  if (s.daemonProcessorArch) daemonVer += ` [${s.daemonProcessorArch}]`;

  const uiVersion = app.getVersion() + ` [${process.arch}]`;

  // disabled functions
  let disabledFunctions = [];
  try {
    for (var propName in s.disabledFunctions) {
      if (!propName || !s.disabledFunctions[propName]) continue;
      disabledFunctions.push(`${propName} (${s.disabledFunctions[propName]})`);
    }
  } catch (e) {
    disabledFunctions.push([`ERROR: ${e}`]);
  }

  // account info
  let accInfo = "";
  try {
    const acc = s.account;
    accInfo = `${acc.accountStatus.CurrentPlan} (${acc.accountStatus.Active ? "Active" : "NOT ACTIVE"
      })`;
    if (acc.session.WgPublicKey)
      accInfo += `; wgKeys=OK ${acc.session.WgKeyGenerated}`;
    else accInfo += "; wgKeys=EMPTY";
  } catch (e) {
    accInfo = `ERROR: ${e}`;
  }

  // last disconnection
  try {
    data[" LastDisconnectionReason"] = "";
    if (
      s.vpnState.disconnectedInfo &&
      s.vpnState.disconnectedInfo.ReasonDescription
    )
      data[" LastDisconnectionReason"] =
        s.vpnState.disconnectedInfo.ReasonDescription;
  } catch (e) {
    data[" LastDisconnectionReason"] = `ERROR: ${e}`;
  }

  data[" Account"] =
    `${s.account.session ? s.account.session.AccountID : "???"}; ` + accInfo;
  if (disabledFunctions.length > 0)
    data[" DisabledFunctions"] = disabledFunctions.join("; ");
  data[" Firewall"] = JSON.stringify(s.vpnState.firewallState, null, 2);
  data[" ParanoidMode"] = s.paranoidModeStatus.IsEnabled ? "On" : "Off";
  data[" SplitTunneling"] = s.vpnState.splitTunnelling.IsEnabled ? "On" : "Off";
  data[" ParanoidMode"] = s.paranoidModeStatus.IsEnabled ? "On" : "Off";
  data[" Version"] = `Daemon=${daemonVer}; UI=${uiVersion}`;
  data[" Settings"] = JSON.stringify(s.settings, null, 2);

  return data;
});
ipcMain.handle(
  "renderer-request-submit-diagnostic-logs",
  async (event, comment, dataObj) => {
    let accountID = "";
    if (store.state.account.session != null)
      accountID = store.state.account.session.AccountID;

    let buildExtraInfo = "";
    if (GetLinuxSnapEnvVars()) {
      buildExtraInfo = "SNAP environement";
    }

    return SentrySendDiagnosticReport(
      accountID,
      comment,
      dataObj,
      store.state.daemonVersion,
      buildExtraInfo
    );
  }
);

// UPDATES
ipcMain.on("renderer-request-app-updates-is-able-to-update", (event) => {
  try {
    event.returnValue = IsAbleToCheckUpdate();
  } catch {
    event.returnValue = false;
  }
});
ipcMain.handle("renderer-request-app-updates-check", async () => {
  return await CheckUpdates();
});
ipcMain.handle("renderer-request-app-updates-upgrade", async () => {
  return await Upgrade();
});
ipcMain.handle("renderer-request-app-updates-cancel-download", async () => {
  return await CancelDownload();
});
ipcMain.handle("renderer-request-app-updates-install", async () => {
  return await Install();
});

// AUTO-LAUNCH
ipcMain.handle("renderer-request-auto-launch-is-enabled", async () => {
  return await AutoLaunchIsEnabled();
});
ipcMain.handle("renderer-request-auto-launch-set", async (event, isEnabled) => {
  return await AutoLaunchSet(isEnabled);
});

// COLOR SCHEME
ipcMain.on("renderer-request-ui-color-scheme-get", (event) => {
  event.returnValue = nativeTheme.themeSource;
});
ipcMain.handle("renderer-request-ui-color-scheme-set", (event, theme) => {
  store.dispatch("settings/colorTheme", theme);
});

// DIALOG
ipcMain.on("renderer-request-showmsgboxsync", (event, diagConfig) => {
  event.returnValue = dialog.showMessageBoxSync(
    event.sender.getOwnerBrowserWindow(),
    diagConfig
  );
});
ipcMain.handle(
  "renderer-request-showmsgbox",
  async (event, diagConfig, doNotAttachToWindow) => {
    if (doNotAttachToWindow === true)
      return await dialog.showMessageBox(diagConfig);

    return await dialog.showMessageBox(
      event.sender.getOwnerBrowserWindow(),
      diagConfig
    );
  }
);

ipcMain.on("renderer-request-showOpenDialogSync", (event, options) => {
  event.returnValue = dialog.showOpenDialogSync(
    event.sender.getOwnerBrowserWindow(),
    options
  );
});
ipcMain.handle("renderer-request-showOpenDialog", async (event, options) => {
  return await dialog.showOpenDialog(
    event.sender.getOwnerBrowserWindow(),
    options
  );
});

// WINDOW

ipcMain.handle("renderer-request-close-current-window", async (event) => {
  return await event.sender.getOwnerBrowserWindow().close();
});
ipcMain.handle("renderer-request-minimize-current-window", async (event) => {
  return await event.sender.getOwnerBrowserWindow().minimize();
});

ipcMain.on("renderer-request-properties-current-window", (event) => {
  const wnd = event.sender.getOwnerBrowserWindow();
  let retVal = null;
  if (wnd)
    retVal = {
      closable: wnd.closable,
      maximizable: wnd.maximizable,
      minimizable: wnd.minimizable,
    };

  event.returnValue = retVal;
});

// SHELL
ipcMain.handle(
  "renderer-request-shell-show-item-in-folder",
  async (event, file) => {
    file = path.normalize(file);
    return await shell.showItemInFolder(file);
  }
);
ipcMain.handle("renderer-request-shell-open-external", async (event, uri) => {
  if (uri == null) return;

  let isAllowedUrl = false;

  for (let p of config.URLsAllowedPrefixes) {
    if (uri == p || uri.startsWith(p)) {
      isAllowedUrl = true;
      break;
    }
  }

  if (!isAllowedUrl) {
    const errMsgText = `The link cannot be opened`;
    const errMsgTextLnk = `${uri}`;
    const errMsgDetail = `Links must start with: "${config.URLsAllowedPrefixes}". Opening links that do not meet this criterion is not allowed.`;
    console.log(errMsgText + " " + errMsgTextLnk + " " + errMsgDetail);

    dialog.showMessageBoxSync(event.sender.getOwnerBrowserWindow(), {
      type: "error",
      message: errMsgText,
      detail: errMsgTextLnk + "\n\n" + errMsgDetail,
      buttons: ["OK"],
    });
    return;
  }
  return shell.openExternal(uri);
});

// OS
ipcMain.on("renderer-request-os-release", (event) => {
  event.returnValue = os.release();
});
ipcMain.on("renderer-request-platform", (event) => {
  event.returnValue = Platform();
});

// APP
ipcMain.on("renderer-request-app-getversion", (event) => {
  event.returnValue = {
    Version: app.getVersion(),
    ProcessorArch: process.arch,
  };
});

// HELPERS
ipcMain.handle("renderer-request-getAppIcon", (event, binaryPath) => {
  return client.GetAppIcon(binaryPath);
});

// PARANOID MODE

ipcMain.handle(
  "renderer-request-setParanoidModePassword",
  async (event, newPassword, oldPassword) => {
    return await client.SetParanoidModePassword(newPassword, oldPassword);
  }
);

ipcMain.handle(
  "renderer-request-setLocalParanoidModePassword",
  async (event, password) => {
    return await client.SetLocalParanoidModePassword(password);
  }
);

// ipcMain.handle(
//   "renderer-request-open-sso-login", async () => {
//     let win = new BrowserWindow({ width: 800, height: 800 });
//     win.loadURL('https://sso.privateline.dev/realms/privateLINE/protocol/openid-connect/auth?client_id=pl-connect-desktop&response_type=code&redirect_uri=http://localhost:5173&scope=openid&state=sandeep');

//     win.webContents.on('did-finish-load', () => {
//       const url = win.webContents.getURL();
//       console.log('Final URL:', url);

//       const urlParams = new URLSearchParams(new URL(url).search);
//       const code = urlParams.get('code');

//       if (code) {
//         console.log('Authorization Code:', code);
//         win.close();
//       }
//     });

//     win.on('closed', () => {
//       win = null;
//     });
//   }
// );

// ======================= Within Same window Start===================
// ipcMain.handle("renderer-request-open-sso-login", async () => {
//   const loginUrl = "https://sso.privateline.dev/realms/privateLINE/protocol/openid-connect/auth?client_id=pl-connect-desktop&response_type=code&redirect_uri=http://localhost:5173&scope=openid&state=sandeep";

//   const winSession = session.fromPartition('persist:winSession', { cache: true });

//   // Optional: Clear session data to avoid conflicts
//   // await winSession.clearStorageData();

//   const win = new BrowserWindow({
//     width: 900,
//     height: 900,
//     show: true,
//     webPreferences: {
//       nodeIntegration: false,
//       contextIsolation: true,
//       enableRemoteModule: false,
//       session: winSession,
//       webSecurity: true,
//     }
//   });

//   win.webContents.setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36');

//   win.loadURL(loginUrl);

//   win.webContents.on('will-navigate', (event, url) => {
//     console.log('Attempting to navigate to:', url);

//     if (url.includes('login-actions/authenticate')) {
//       event.preventDefault();
//       win.loadURL(url);
//     }

//     if (url.startsWith('http://localhost:5173')) {
//       event.preventDefault();
//       const urlParams = new URLSearchParams(new URL(url).search);
//       const code = urlParams.get('code');

//       if (code) {
//         console.log('Authorization Code:', code);
//         win.close();
//       }
//     }
//   });

//   win.webContents.on('did-navigate', (event, url) => {
//     console.log('Navigated to:', url);

//     if (url.startsWith('http://localhost:5173')) {
//       const urlParams = new URLSearchParams(new URL(url).search);
//       const code = urlParams.get('code');

//       if (code) {
//         console.log('Authorization Code:', code);
//         win.close();
//       }
//     }
//   });

//   win.webContents.on('did-fail-load', (event, errorCode, errorDescription, validatedURL) => {
//     console.error('Failed to load URL:', validatedURL, 'Error:', errorDescription);
//   });

//   // win.webContents.session.webRequest.onBeforeRequest((details, callback) => {
//   //   console.log('Request Details:', details);
//   //   callback({});
//   // });

//   win.on('closed', () => {
//     win = null;
//   });

//   // Optional: Monitor cookies to ensure they are being set correctly
//   // winSession.cookies.on('changed', (event, cookie, cause, removed) => {
//   //   console.log('Cookie changed:', cookie);
//   // });
// });
// ======================= Within Same window End=====================


// ======================= External Shell window Start================
// TODO: SSO Login 

ipcMain.handle("renderer-request-open-sso-login", async () => {

  // Open the login URL in the default web browser
  const loginUrl = "https://sso.privateline.dev/realms/privateLINE/protocol/openid-connect/auth?client_id=pl-connect-desktop&response_type=code&redirect_uri=http://localhost:5173&scope=openid&state=sandeep";

  // shell.openExternal(loginUrl);

  // Create an isolated session for the hidden window
  const winSession = session.fromPartition('persist:ssoSession', { cache: true });
  await winSession.clearStorageData(); // Clear previous session data to avoid conflicts

  let win = new BrowserWindow({
    width: 900,
    height: 900,
    show: true,
    webPreferences: {
      nodeIntegration: false, // Node integration disabled for security
      contextIsolation: true,  // Context isolation enabled for security
      sandbox: true,           // Enable sandbox for better security
      session: winSession,
      webSecurity: true,
    }
  });

  win.loadURL(loginUrl)

  // Open DevTools for debugging
  win.webContents.openDevTools();

  // Set user agent to a modern browser
  win.webContents.setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36');

  // Handle URL navigation
  win.webContents.on('will-navigate', (event, url) => {
    console.log('Attempting to navigate to:', url);

     // Manually allow the navigation if the URL matches your criteria
  if (url.includes('login-actions/authenticate') || url.startsWith('http://localhost:5173')) {
    event.preventDefault(); // Prevent Electron's default behavior
    win.loadURL(url); // Manually navigate to the URL
  }
  });

  win.webContents.on('did-navigate', (event, url) => {
    console.log('Navigated to:', url);

    if (url.startsWith('http://localhost:5173')) {
      const urlParams = new URLSearchParams(new URL(url).search);
      const code = urlParams.get('code');

      if (code) {
        console.log('Authorization Code:', code);
        win.close();
      }
    }
  });

  win.webContents.on('did-fail-load', (event, errorCode, errorDescription, validatedURL) => {
    console.error('Failed to load URL:', validatedURL, 'Error:', errorDescription);
  });

  win.on('closed', () => {
    win = null;
  });

  // winSession.webRequest.onBeforeRequest({ urls: ['http://localhost:5173/*'] }, (details, callback) => {
  //   const url = details.url;
  //   console.log('Intercepted request to:', url);
  
  //   const urlParams = new URLSearchParams(new URL(url).search);
  //   const code = urlParams.get('code');
  
  //   if (code) {
  //     console.log('Authorization Code:', code);
  //     win.close();
  //   }
  
  //   callback({ cancel: false });
  // });
});


// ======================= External Shell window End================





