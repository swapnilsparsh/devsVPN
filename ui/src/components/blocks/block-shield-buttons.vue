<template>
  <div>
    <div class="small_text">Connection type</div>
    <div class="shieldButtons">
      <div />
      <button class="shieldButton" v-bind:class="{
        shieldButtonActive: IsEnabled,
      }" v-on:click="ChangeShield(true)">
        Shield
      </button>

      <div />

      <button class="shieldButton" v-bind:class="{
        shieldButtonActive: !IsEnabled,
      }" v-on:click="ChangeShield(false)">
        Total Shield
      </button>

      <div />
    </div>
  </div>
</template>

<script>

const sender = window.ipcSender;

import { Platform, PlatformEnum } from "@/platform/platform";

import Image_search_windows from "@/assets/search-windows.svg";
import Image_search_macos from "@/assets/search-macos.svg";
import Image_search_linux from "@/assets/search-linux.svg";

import ComponentDialog from "@/components/component-dialog.vue";
import binaryInfoControl from "@/components/controls/control-app-binary-info.vue";

import spinner from "@/components/controls/control-spinner.vue";
import linkCtrl from "@/components/controls/control-link.vue";


export default {
  components: {
    spinner,
    binaryInfoControl,
    ComponentDialog,
    linkCtrl,
  },

  data: function () {
    return {
      isSTEnabledLocal: false,
      stInversedLocal: false,
      stAnyDnsLocal: false,
      stBlockNonVpnDnsLocal: true,
      stAllowWhenNoVpnLocal: false,

      isLoadingAllApps: false,
      isShowAppAddPopup: false,

      filterAppsToAdd: "",

      // allInstalledApps [] - an array of applications installed on users device
      //                       (in use in Split Tunnel mode)
      // Type (AppInfo):
      //    AppName       string
      //    AppGroup      string // optional
      //    AppIcon       string - base64 icon of the executable binary
      //    AppBinaryPath string - The unique parameter describing an application
      //                    Windows: absolute path to application binary
      //                    Linux: program to execute, possibly with arguments.
      allInstalledApps: null,
      allInstalledAppsHashed: {},

      // []AppInfoEx -  configured (running) apps
      // Type:
      //  AppInfo fields
      //  + RunningApp: (Linux: info about running apps in ST environment):
      //      RunningApp.Pid     int
      //      RunningApp.Ppid    int        // The PID of the parent of this process.
      //      RunningApp.Cmdline string
      //      RunningApp.Exe     string     // The actual pathname of the executed command
      //      RunningApp.ExtIvpnRootPid int // PID of the known parent process registered by AddPid() function
      //      RunningApp.ExtModifiedCmdLine string
      appsToShow: null,
    };
  },

  computed: {
    textApplicationsHeader: function () {
      if (Platform() === PlatformEnum.Linux) return "Launched applications";
      return "Applications";
    },

    textNoAppInSplittunConfig: function () {
      return "No applications in Split Tunnel configuration";
    },

    textAddAppButton: function () {
      if (Platform() === PlatformEnum.Linux) return "Launch application...";
      return "Add application...";
    },
    textAddAppFromInstalledAppsHeader: function () {
      if (Platform() === PlatformEnum.Linux)
        return "Launch application in Split Tunnel configuration";
      return "Add application to Split Tunnel configuration";
    },
    textAddAppManuallyButton: function () {
      if (Platform() === PlatformEnum.Linux)
        return "Launch application manually...";
      return "Add application manually ...";
    },

    isLinux: function () {
      return Platform() === PlatformEnum.Linux;
    },

    isSplitTunnelInverseSupported() {
      return this.$store.getters["isSplitTunnelInverseEnabled"];
    },

    // needed for 'watch'
    IsEnabled: function () {
      return this.$store.state.vpnState.splitTunnelling?.IsEnabled;
    },
    // needed for 'watch'
    IsInversed: function () {
      return this.$store.state.vpnState.splitTunnelling?.IsInversed;
    },
    // needed for 'watch'
    IsAnyDns: function () {
      return this.$store.state.vpnState.splitTunnelling?.IsAnyDns;
    },
    IsAllowWhenNoVpn: function () {
      return this.$store.state.vpnState.splitTunnelling?.IsAllowWhenNoVpn;
    },

    // needed for 'watch'
    STConfig: function () {
      return this.$store.state.vpnState.splitTunnelling;
    },

    isNoConfiguredApps: function () {
      if (
        this.isLoadingAllApps == false &&
        (!this.appsToShow || this.appsToShow.length == 0)
      )
        return true;
      return false;
    },

    filteredApps: function () {
      return this.appsToShow;
    },

    filteredAppsToAdd: function () {
      let retInstalledApps =
        this.$store.getters["settings/getAppsToSplitTunnel"];
      // filter: exclude already configured apps (not a running apps)
      // from the list installed apps
      if (!this.isLinux) {
        let confAppsHashed = {};
        this.appsToShow.forEach((appInfo) => {
          confAppsHashed[appInfo.AppBinaryPath.toLowerCase()] = appInfo;
        });
        let funcFilter = function (appInfo) {
          let confApp = confAppsHashed[appInfo.AppBinaryPath.toLowerCase()];
          if (confApp && (!confApp.RunningApp || !confApp.RunningApp.Pid))
            return false;
          return true;
        };
        retInstalledApps = retInstalledApps.filter((appInfo) =>
          funcFilter(appInfo),
        );
      }

      // filter: default (filtering apps according to user input)
      let filter = this.filterAppsToAdd.toLowerCase();
      if (filter && filter.length > 0) {
        let funcFilter = function (appInfo) {
          return (
            appInfo.AppName.toLowerCase().includes(filter) ||
            appInfo.AppGroup.toLowerCase().includes(filter)
          );
        };
        retInstalledApps = retInstalledApps.filter((appInfo) =>
          funcFilter(appInfo),
        );
      }

      return retInstalledApps;
    },

    searchImageInstalledApps: function () {
      if (this.filterAppsToAdd) return null;

      switch (Platform()) {
        case PlatformEnum.Windows:
          return Image_search_windows;
        case PlatformEnum.macOS:
          return Image_search_macos;
        default:
          return Image_search_linux;
      }
    },
  },

  async mounted() {
    this.isSTEnabledLocal = this.IsEnabled;
    this.stInversedLocal = this.IsInversed;
    this.stBlockNonVpnDnsLocal = !this.IsAnyDns;
    this.stAllowWhenNoVpnLocal = this.IsAllowWhenNoVpn;

    // show base information about splitted apps immediately
    //this.updateAppsToShow();

    let allApps = null;
    try {
      this.isLoadingAllApps = true;
      allApps = await sender.GetInstalledApps();
      await sender.SplitTunnelGetStatus();
    } finally {
      this.isLoadingAllApps = false;
    }

    if (allApps) {
      // create a list of hashed appinfo (by app path)
      allApps.forEach((appInfo) => {
        this.allInstalledAppsHashed[appInfo.AppBinaryPath.toLowerCase()] =
          appInfo;
      });

      this.allInstalledApps = allApps;
    }

    // now we are able to update information about splitted apps
    this.updateAppsToShow();
  },

  watch: {
    IsEnabled() {
      this.isSTEnabledLocal = this.IsEnabled;
    },
    IsInversed() {
      this.stInversedLocal = this.IsInversed;
    },
    IsAnyDns() {
      this.stBlockNonVpnDnsLocal = !this.IsAnyDns;
    },
    IsAllowWhenNoVpn() {
      this.stAllowWhenNoVpnLocal = this.IsAllowWhenNoVpn;
    },

    STConfig() {
      this.updateAppsToShow();
      // if there are running apps - start requesting ST status
      this.startBackgroundCheckOfStatus();
    },
  },

  methods: {
    async ChangeHop(isMultihop) {
      if (this.$store.state.settings.isMultiHop === isMultihop) return;

      this.$store.dispatch(
        `settings/isMultiHop`,
        !this.$store.state.settings.isMultiHop,
      );

      if (
        this.$store.getters["vpnState/isConnected"] ||
        this.$store.getters["vpnState/isConnecting"]
      ) {
        // Re-connect
        try {
          await sender.Connect();
        } catch (e) {
          console.error(e);
          sender.showMessageBoxSync({
            type: "error",
            buttons: ["OK"],
            message: `Failed to connect: ` + e,
          });
        }
      }
    },
    async ChangeShield(value) {
      //============== Write here Shield logic and remember there is much more than this
      //this is simple split tunnel as shield and not split tunnel as full shield as discussed with satyarth
      // value = true means split tunnel 
      this.isSTEnabledLocal = value
      // APPLY ST CONFIGURATION
      try {
        await sender.SplitTunnelSetConfig(
          this.isSTEnabledLocal,
          this.stInversedLocal,
          !this.stBlockNonVpnDnsLocal, // isAnyDns,
          this.stAllowWhenNoVpnLocal,
        );
        // Change switch connection color based on shield and total shield button selected
        if (value) {
          document.documentElement.style.setProperty('--connection-switch-color', '#4EAF51');
        } else {
          document.documentElement.style.setProperty('--connection-switch-color', '#0766FF');
        }
      } catch (e) {
        processError(e);
      }
      // ensure local value synced with data from storage
      // AND ensure that UI state of checkboxes updated!
      this.updateLocals();
    },

    showServersList(isExitServer) {
      this.onShowServersPressed(isExitServer);
    },

    // ======= Split methods =======
    updateLocals() {
      this.isSTEnabledLocal = this.IsEnabled;
      this.stInversedLocal = this.IsInversed;
      this.stBlockNonVpnDnsLocal = !this.IsAnyDns;
      this.stAllowWhenNoVpnLocal = this.IsAllowWhenNoVpn;
    },
    async applyChanges() {
      let fwState = this.$store.state.vpnState.firewallState;
      let oldInverseMode = this.IsEnabled && this.IsInversed;
      let newInverseMode = this.isSTEnabledLocal && this.stInversedLocal;

      // going to enable Inverse ST
      if (fwState.IsEnabled && !oldInverseMode && newInverseMode) {
        let extraMessage = "";
        if (fwState.IsPersistent)
          extraMessage =
            "\n\nNote! The always-on firewall is enabled. If you disable the firewall the 'always-on' feature will be disabled.\n";

        try {
          let ret = await sender.showMessageBoxSync(
            {
              type: "warning",
              message: `Turning off Firewall for Inverse Split Tunnel mode`,
              detail: `The Inverse Split Tunnel mode requires disabling the privateLINE Firewall.${extraMessage}\nWould you like to proceed?`,
              buttons: ["Disable Firewall", "Cancel"],
            },
            true,
          );
          if (ret == 1) {
            // cancel
            this.updateLocals();
            return;
          }
          if (fwState.IsPersistent)
            await sender.KillSwitchSetIsPersistent(false);
          await sender.EnableFirewall(false);
        } catch (e) {
          processError(e);
        }
      }

      // APPLY ST CONFIGURATION
      try {
        await sender.SplitTunnelSetConfig(
          this.isSTEnabledLocal,
          this.stInversedLocal,
          !this.stBlockNonVpnDnsLocal, // isAnyDns,
          this.stAllowWhenNoVpnLocal,
        );
      } catch (e) {
        processError(e);
      }
      // ensure local value synced with data from storage
      // AND ensure that UI state of checkboxes updated!
      this.updateLocals();

      // If VPN is connected and Inverse mode is just disabled - ask user to enable Firewall
      if (
        !newInverseMode &&
        oldInverseMode &&
        !fwState.IsEnabled &&
        !this.$store.getters["vpnState/isPaused"] && // we can not enable firewall in paused state
        this.$store.getters["vpnState/isConnected"] // no need to enable firewall if VPN is not connected
      )
        try {
          let ret = await sender.showMessageBoxSync(
            {
              type: "question",
              message: `The privateLINE Firewall is not enabled`,
              detail:
                "The Inverse Split Tunnel mode has been disabled successfully. You can now use the Firewall.\n\nWould you like to enable the privateLINE Firewall?",
              buttons: ["Enable Firewall", "Cancel"],
            },
            true,
          );
          if (ret == 1) return; // cancel
          await sender.EnableFirewall(true);
        } catch (e) {
          processError(e);
        }
    },

    async onSTInversedChange() {
      let cancel = false;

      if (this.IsInversed === false) {
        // going to enable
        let ret = await sender.showMessageBoxSync(
          {
            type: "warning",
            message: `Enabling Inverse mode for Split Tunnel`,
            detail:
              "By enabling Inverse Split Tunnel, only specified apps will use the VPN tunnel while the rest of your system will keep using the default connection, bypassing the VPN tunnel.\n\
Note! The privateLINE Firewall is not functional when this feature is enabled.\n\n\
Do you want to enable Inverse mode for Split Tunnel?",
            buttons: ["Enable", "Cancel"],
          },
          true,
        );
        if (ret == 1) cancel = true; // cancel
      }

      if (!cancel) {
        await this.applyChanges();
      } else {
        // ensure local value synced with data from storage
        // AND ensure that UI state of checkboxes updated!
        this.updateLocals();
      }
    },
    isRunningAppsAvailable() {
      let stStatus = this.$store.state.vpnState.splitTunnelling;
      return (
        Array.isArray(stStatus.RunningApps) && stStatus.RunningApps.length > 0
      );
    },
    stopBackgroundCheckOfStatus() {
      if (timerBackgroundCheckOfStatus != 0) {
        clearInterval(timerBackgroundCheckOfStatus);
        timerBackgroundCheckOfStatus = 0;
      }
    },
    startBackgroundCheckOfStatus() {
      if (Platform() !== PlatformEnum.Linux) return;
      // timer already started
      if (timerBackgroundCheckOfStatus) return;

      if (this.isRunningAppsAvailable()) {
        timerBackgroundCheckOfStatus = setInterval(() => {
          if (
            !this.isRunningAppsAvailable() ||
            this.$store.state.uiState.currentSettingsViewName != "splittunnel"
          ) {
            this.stopBackgroundCheckOfStatus();
            return;
          }
          try {
            sender.SplitTunnelGetStatus();
          } catch (e) {
            console.error(e);
          }
        }, 5000);
      }
    },

    updateAppsToShow() {
      // preparing list of apps to show (AppInfo fields + RunningApp)
      let appsToShowTmp = [];

      try {
        let splitTunnelling = this.$store.state.vpnState.splitTunnelling;
        if (Platform() === PlatformEnum.Linux) {
          // Linux:
          let runningApps = splitTunnelling.RunningApps;
          runningApps.forEach((runningApp) => {
            // check if we can get info from the installed apps list
            let cmdLine = "";
            if (
              runningApp.ExtModifiedCmdLine &&
              runningApp.ExtModifiedCmdLine.length > 0
            ) {
              cmdLine = runningApp.ExtModifiedCmdLine.toLowerCase();
            } else {
              cmdLine = runningApp.Cmdline.toLowerCase();
            }

            let knownApp = this.allInstalledAppsHashed[cmdLine];
            // Do not show child processes (child processes of known root PID)
            if (
              runningApp.ExtIvpnRootPid > 0 &&
              runningApp.ExtIvpnRootPid !== runningApp.Pid
            )
              return;
            if (!knownApp)
              // app is not found in 'installed apps list'
              appsToShowTmp.push({
                AppBinaryPath: cmdLine,
                AppName: cmdLine,
                AppGroup: null,
                RunningApp: runningApp,
              });
            else {
              // app is found in 'installed apps list'
              // use 'Object.assign' to not update data in 'this.allInstalledAppsHashed'
              knownApp = Object.assign({}, knownApp);
              knownApp.RunningApp = runningApp;
              appsToShowTmp.push(Object.assign({}, knownApp));
            }
          });
        } else {
          // Windows:
          let configApps = splitTunnelling.SplitTunnelApps;
          configApps.forEach((appPath) => {
            if (!appPath) return;
            // check if we can get info from the installed apps list
            let knownApp = this.allInstalledAppsHashed[appPath.toLowerCase()];
            if (!knownApp) {
              // app is not found in 'installed apps list'
              appsToShowTmp.push({
                AppBinaryPath: appPath,
                AppName: getFileName(appPath),
                AppGroup: getFileFolder(appPath),
              });
            } else {
              // app is found in 'installed apps list'
              // use 'Object.assign' to not update data in 'this.allInstalledAppsHashed'
              appsToShowTmp.push(Object.assign({}, knownApp));
            }
          });
        }
      } catch (e) {
        console.error(e);
      }

      // sorting the list
      appsToShowTmp.sort(function (a, b) {
        if (a.RunningApp && b.RunningApp) {
          if (
            a.RunningApp.ExtIvpnRootPid > 0 &&
            b.RunningApp.ExtIvpnRootPid === 0
          )
            return -1;
          if (
            a.RunningApp.ExtIvpnRootPid === 0 &&
            b.RunningApp.ExtIvpnRootPid > 0
          )
            return 1;

          if (a.RunningApp.Pid < b.RunningApp.Pid) return -1;
          if (a.RunningApp.Pid > b.RunningApp.Pid) return 1;
        }

        if (a.AppName && b.AppName) {
          let app1 = a.AppName.toUpperCase();
          let app2 = b.AppName.toUpperCase();
          if (app1 > app2) return 1;
          if (app1 < app2) return -1;
        } else {
          if (a.AppName > b.AppName) return 1;
          if (a.AppName < b.AppName) return -1;
        }
        return 0;
      });

      this.appsToShow = appsToShowTmp;
    },

    showAddApplicationPopup(isShow) {
      this.resetFilters();

      if (isShow === true) {
        this.filterAppsToAdd = "";
        let appsToAdd = this.filteredAppsToAdd;
        if (!appsToAdd || appsToAdd.length == 0) {
          // if no info about all installed applications - show dialog to manually select binary
          this.addApp(null);
          return;
        }
        this.isShowAppAddPopup = true;
        setTimeout(() => {
          try {
            this.$refs.installedAppsFilterInput.focus();
          } catch (e) {
            console.error(e);
          }
        }, 0);
      } else this.isShowAppAddPopup = false;
    },

    async removeApp(app) {
      try {
        if (!app) return;
        if (app.RunningApp)
          await sender.SplitTunnelRemoveApp(
            app.RunningApp.Pid,
            app.AppBinaryPath,
          );
        else await sender.SplitTunnelRemoveApp(0, app.AppBinaryPath);
      } catch (e) {
        processError(e);
      } finally {
        this.showAddApplicationPopup(false);
      }
    },

    async addApp(appPath) {
      try {
        await sender.SplitTunnelAddApp(appPath);
      } catch (e) {
        processError(e);
      } finally {
        this.showAddApplicationPopup(false);
      }
    },

    async onResetToDefaultSettings() {
      let actionNo = sender.showMessageBoxSync({
        type: "question",
        buttons: ["Yes", "Cancel"],
        message: "Reset all settings to default values",
        detail: `Are you sure you want to reset the Split Tunnel configuration for all applications?`,
      });
      if (actionNo == 1) return;

      this.resetFilters();
      await sender.SplitTunnelSetConfig(false, false, false, false, true);
    },

    resetFilters: function () {
      this.filterAppsToAdd = "";
    },
  },
};
</script>

<!-- Add "scoped" attribute to limit CSS to this component only -->
<style scoped lang="scss"></style>
<style scoped lang="scss">
@import "@/components/scss/constants";
@import "@/components/scss/platform/base.scss";

.grayedOnHover:hover {
  background: rgba(100, 100, 100, 0.2);
  border-radius: 2px;
}

.opacityOnHover:hover {
  opacity: 0.6;
}

.opacityOnHoverLight:hover {
  opacity: 0.8;
}

.defColor {
  @extend .settingsDefaultTextColor;
}

div.fwDescription {
  @extend .settingsGrayLongDescriptionFont;
  margin-top: 4px;
  margin-bottom: 8px;
  margin-left: 22px;
  max-width: 425px;
}

div.param {
  @extend .flexRow;
  margin-top: 3px;
}

button.link {
  @extend .noBordersTextBtn;
  @extend .settingsLinkText;
  font-size: inherit;
}

label {
  margin-left: 1px;
}

input#filter {
  margin-left: 20px;
  margin-right: 20px;
  margin-top: 0px;
  margin-bottom: 0px;
  height: auto;

  background-position: 97% 50%; //right
  background-repeat: no-repeat;
}

button:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}

button:disabled+label {
  opacity: 0.6;
  cursor: not-allowed;
}

input:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}

input:disabled+label {
  opacity: 0.6;
  cursor: not-allowed;
}

$popup-background: var(--background-color);
$shadow: 0px 3px 12px rgba(var(--shadow-color-rgb), var(--shadow-opacity));

.appsSelectionPopup {
  position: absolute;
  z-index: 1;

  height: 100%;
  width: 100%;

  padding: 15px;
  height: 450px; //calc(100% + 140px);
  width: calc(100% + 10px);
  left: -20px;
  top: 0px;

  border-width: 1px;
  border-style: solid;
  border-color: $popup-background;

  //border-radius: 8px;
  background-color: $popup-background;
  box-shadow: $shadow;
}
.small_text {
  font-size: 14px;
  line-height: 17px;
  letter-spacing: -0.3px;
  color: var(--text-color-details);
  margin-left: 20px;
}
</style>