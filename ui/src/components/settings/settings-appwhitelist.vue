<template>
  <div class="flexColumn">
    <div class="settingsTitle flexRow">APP WHITELIST SETTINGS</div>

    <!-- SELECT apps 'popup' view -->
    <div ref="appsListParent" class="flexRow" style="position: relative">
      <transition name="fade-super-quick" mode="out-in">
        <div v-if="isShowAppAddPopup" class="appsSelectionPopup">
          <div>
            <div class="flexRow" style="margin-bottom: 10px">
              <div class="flexRowRestSpace settingsGrayTextColor">
                {{ textAddAppFromInstalledAppsHeader }}
              </div>

              <button class="noBordersBtn opacityOnHoverLight settingsGrayTextColor" style="pointer-events: auto"
                v-on:click="showAddApplicationPopup(false)">
                CANCEL
              </button>
            </div>

            <!-- filter -->
            <input ref="installedAppsFilterInput" id="filter" class="styled" placeholder="Search for app"
              v-model="filterAppsToAdd" v-bind:style="{
                backgroundImage: 'url(' + searchImageInstalledApps + ')',
              }" style="margin: 0px; margin-bottom: 10px" />
            <div class="horizontalLine" />

            <!--all apps-->
            <div style="
                overflow: auto;
                position: relative;
                height: 320px;
                max-height: 320px;
              ">
              <!-- No applications that are fit the filter -->
              <div v-if="!filteredAppsToAdd || filteredAppsToAdd.length == 0"
                style="text-align: center; width: 100%; margin-top: 100px">
                <div class="settingsGrayTextColor">
                  No applications that are fit the filter:
                </div>
                <div>
                  '<span class="settingsGrayTextColor" style="
                      display: inline-block;
                      font-weight: bold;
                      overflow: hidden;
                      white-space: nowrap;
                      text-overflow: ellipsis;
                      max-width: 300px;
                    ">{{ filterAppsToAdd }}</span>'
                </div>
              </div>

              <div v-else v-for="app of filteredAppsToAdd" v-bind:key="app.AppBinaryPath">
                <div v-on:click="addApp(app.AppBinaryPath)" class="flexRow grayedOnHover" style="padding-top: 4px">
                  <binaryInfoControl :app="app" style="width: 100%" />
                </div>
              </div>
            </div>
            <div style="height: 100%" />
            <div class="horizontalLine" />

            <div>
              <button class="settingsButton flexRow grayedOnHover" style="
                  margin-top: 10px;
                  margin-bottom: 10px;
                  height: 40px;
                  width: 100%;
                " v-on:click="addApp(null)">
                <div class="flexRowRestSpace"></div>
                <div class="flexRow">
                  <img width="24" height="24" style="margin: 8px" src="@/assets/plus.svg" />
                </div>
                <div class="flexRow settingsGrayTextColor">
                  {{ textAddAppManuallyButton }}
                </div>
                <div class="flexRowRestSpace"></div>
              </button>
            </div>
          </div>
        </div>
      </transition>
    </div>

    <div class="param">
      <input type="checkbox" id="isAppWhitelistEnabledLocal" v-model="isAppWhitelistEnabledLocal" @change="applyChanges" />
      <label class="defColor" for="isAppWhitelistEnabledLocal">App Whitelist</label>
      <button class="noBordersBtn flexRow" title="Help" v-on:click="$refs.helpAppWhitelistEnabledLocal.showModal()">
        <img src="@/assets/question.svg" />
      </button>
      <!-- ============= TODO SPLIT Tunnel ================= -->
      <ComponentDialog ref="helpAppWhitelistEnabledLocal" header="Info">
        <div>
          <p>
            Allow only whitelisted applications to access privateLINE enclave
          </p>
          <!-- functionality description: LINUX -->
          <p v-if="isLinux">
            Shield mode: whitelisted applications will be allowed access to
            privateLINE enclave and the internet. Other applications will be
            allowed access to the internet, but not to the privateLINE enclave.
            <br><br>
            Total Shield mode: Whitelisted applications will be allowed access 
            to the privateLINE enclave, but not to the internet. Other 
            applications will not have any external network connectivity, 
            will only be allowed localhost networking.
            <br><br>
            <span style="font-weight: bold">Warning:</span>
            Applications must be launched from the "{{ textAddAppButton }}"
            button. Already running applications or instances can not use App
            Whitelist. Some applications using shared resources (e.g. Web
            browsers) must be closed before launching them or they may not be
            processed properly.
          </p>
          <!-- functionality description: WINDOWS -->
          <div v-else>
            <p>
              <span style="font-weight: bold">Warning:</span>
              When adding a running application to App Whitelist, any 
              connections already established by the application may continue
              to be routed outside of the enclave until the TCP connection/s
              are reset or the application is restarted.
            </p>
          </div>
          <div class="settingsGrayLongDescriptionFont">
            For more information refer to the webpage
          </div>
        </div>
      </ComponentDialog>
    </div>
    <div class="fwDescription">
      Allow only whitelisted applications to access privateLINE enclave
    </div>

    <!-- INVERSE MODE-->
    <!-- Vlad: disabled showing -->
    <!--<div v-show="isSplitTunnelInverseSupported">-->
    <div v-show="false">  
      <!-- Inverse mode -->  
      <div class="param">
        <input :disabled="!isSTEnabledLocal" type="checkbox" id="stInversedLocal" v-model="stInversedLocal"
          @change="onSTInversedChange" />
        <label class="defColor" for="stInversedLocal">Inverse mode (BETA)</label>
        <button class="noBordersBtn flexRow" title="Help" v-on:click="$refs.helpStInversedLocal.showModal()">
          <img src="@/assets/question.svg" />
        </button>
        <ComponentDialog ref="helpStInversedLocal" header="Info">
          <div>
            <p>
              When activated (alongside the Split Tunnel option), it reverses
              the split tunneling behavior. Specified applications utilize the
              VPN connection, while all other traffic circumvents the VPN, using
              the default connection.
            </p>
            <div class="settingsGrayLongDescriptionFont">
              The privateLINE Firewall is not functional when this feature is enabled.
            </div>
          </div>
        </ComponentDialog>
      </div>

      <div class="fwDescription">
        Only specified applications utilize the VPN connection.
      </div>

      <div style="margin-left: 16px">
        <!-- Allow connectivity for Split Tunnel apps when VPN is disabled -->
        <div class="param">
          <input :disabled="!stInversedLocal || !isAppWhitelistEnabledLocal" type="checkbox" id="stAllowWhenNoVpnLocal"
            v-model="stAllowWhenNoVpnLocal" @change="applyChanges" />
          <label class="defColor" for="stAllowWhenNoVpnLocal">
            Allow connectivity for Split Tunnel apps when VPN is disabled</label>
          <button class="noBordersBtn flexRow" title="Help" v-on:click="$refs.helpStAllowWhenNoVpnLocal.showModal()">
            <img src="@/assets/question.svg" />
          </button>
          <ComponentDialog ref="helpStAllowWhenNoVpnLocal" header="Info">
            <div>
              <p>
                Enabling this feature allows applications within the Split
                Tunnel environment to utilize the default network connection
                when the VPN is disabled, mirroring the behavior of applications
                outside the Split Tunnel environment.
              </p>
              <p>
                By default, this feature is turned off, and applications within
                the Split Tunnel environment won't have access to the default
                network interface when the VPN is disabled.
              </p>
            </div>
          </ComponentDialog>
        </div>

        <!-- Block DNS servers not specified by the privateLINE application -->
        <div class="param">
          <input :disabled="!stInversedLocal || !isAppWhitelistEnabledLocal" type="checkbox" id="stBlockNonVpnDnsLocal"
            v-model="stBlockNonVpnDnsLocal" @change="applyChanges" />
          <label class="defColor" for="stBlockNonVpnDnsLocal">Block DNS servers not specified by the privateLINE
            application</label>
          <button class="noBordersBtn flexRow" title="Help" v-on:click="$refs.helpStInversedAnyDns.showModal()">
            <img src="@/assets/question.svg" />
          </button>
          <ComponentDialog ref="helpStInversedAnyDns" header="Info">
            <div>
              <p>
                When this option is enabled, only DNS requests directed to privateLINE
                DNS servers or user-defined custom DNS servers within the privateLINE
                app settings will be allowed. All other DNS requests on port 53
                will be blocked.
              </p>
              <p>
                For enhanced privacy, it is recommended to keep this option
                enabled. Disabling it may result in your apps using the default
                DNS configuration.
              </p>
              <div class="settingsGrayLongDescriptionFont">
                The privateLINE AntiTracker and custom DNS are not functional when this
                feature is disabled.
              </div>
              <div class="settingsGrayLongDescriptionFont">
                This functionality only applies in Inverse Split Tunnel mode
                when the VPN is connected.
              </div>
            </div>
          </ComponentDialog>
        </div>
      </div>
    </div>

    <!-- APPS -->
    <div style="height: 100%">
      <!-- HEADER: Applications -->
      <div class="flexRow" style="margin-top: 12px; margin-bottom: 12px">
        <div class="flexRowRestSpace settingsBoldFont settingsDefaultTextColor"
          style="margin-top: 0px; margin-bottom: 0px; white-space: nowrap">
          {{ textApplicationsHeader }}
        </div>

        <!-- ADD APP BUTTON -->
        <div>
          <button class="settingsButton" v-bind:class="{ opacityOnHoverLight: IsAppWhitelistEnabled === true }"
            :disabled="IsAppWhitelistEnabled !== true" style="min-width: 156px" v-on:click="showAddApplicationPopup(true)">
            {{ textAddAppButton }}
          </button>
        </div>
      </div>

      <div class="horizontalLine" />
      <div ref="appsListParent" class="flexRow" style="position: relative">
        <!-- Configured apps view -->

        <!-- No applications in Split Tunnel configuration -->
        <div v-if="isNoConfiguredApps" style="
            text-align: center;
            width: 100%;
            margin-top: 35px;
            padding: 50px;
          ">
          <div class="settingsGrayTextColor">
            {{ textNoAppInAppWhitelist }}
          </div>
        </div>

        <!-- Configured apps list -->
        <div v-if="!isShowAppAddPopup && !isNoConfiguredApps" :style="`overflow: auto; width: 100%; height: ${$refs.footer.offsetTop - $refs.appsListParent.offsetTop
          }px;`">
          <spinner :loading="isLoadingAllApps" style="
              position: absolute;
              background: transparent;
              width: 100%;
              height: 100%;
            " />

          <div v-for="app of filteredApps" v-bind:key="app.RunningApp ? app.RunningApp.Pid : app.AppBinaryPath">
            <div class="flexRow grayedOnHover" style="padding-top: 4px">
              <!-- APP INFO  -->
              <binaryInfoControl :app="app" style="width: 100%" />
              <!-- APP REMOVE BUTTON -->
              <div>
                <button class="noBordersBtn opacityOnHover" v-on:click="removeApp(app)" style="pointer-events: auto"
                  title="Remove">
                  <img width="24" height="24" src="@/assets/minus.svg" />
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- FOOTER -->

    <div ref="footer" style="position: sticky; bottom: 20px">
      <div class="horizontalLine" />

      <div class="flexRow" style="margin-top: 15px">
        <div class="flexRowRestSpace" />
        <button class="settingsButton opacityOnHoverLight" v-on:click="onResetToDefaultSettings"
          style="white-space: nowrap">
          Reset to default settings
        </button>
      </div>
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

function processError(e) {
  let errMes = e.toString();

  if (errMes && errMes.length > 0) {
    errMes = errMes.charAt(0).toUpperCase() + errMes.slice(1);
  }

  console.error(e);
  sender.showMessageBox({
    type: "error",
    buttons: ["OK"],
    message: errMes,
  });
}

let timerBackgroundCheckOfStatus = 0;

export default {
  components: {
    spinner,
    binaryInfoControl,
    ComponentDialog,
    linkCtrl,
  },

  data: function () {
    return {
      isSTEnabledLocal: true,
      isAppWhitelistEnabledLocal: false,
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

  async mounted() {
    this.isSTEnabledLocal = this.IsEnabled;
    this.isAppWhitelistEnabledLocal = this.IsAppWhitelistEnabled;
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
    IsAppWhitelistEnabled() {
      this.isAppWhitelistEnabledLocal = this.IsAppWhitelistEnabled;
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
    updateLocals() {
      this.isSTEnabledLocal = this.IsEnabled;
      this.isAppWhitelistEnabledLocal = this.IsAppWhitelistEnabled;
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
          // await sender.EnableFirewall(false); // must never disable firewall from client, firewall must always remain enabled
        } catch (e) {
          processError(e);
        }
      }

      // APPLY ST CONFIGURATION
      try {
        await sender.SplitTunnelSetConfig(
          this.isSTEnabledLocal,
          this.stInversedLocal,
          this.isAppWhitelistEnabledLocal,
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
            this.$store.state.uiState.currentSettingsViewName != "appwhitelist"
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
        detail: `Are you sure you want to reset the App Whitelist configuration for all applications?`,
      });
      if (actionNo == 1) return;

      this.resetFilters();
      await sender.SplitTunnelSetConfig(true, true, false, false, false, true);
    },

    resetFilters: function () {
      this.filterAppsToAdd = "";
    },
  },

  computed: {
    textApplicationsHeader: function () {
      if (Platform() === PlatformEnum.Linux) return "Running Whitelisted Applications";
      return "Applications";
    },

    textNoAppInAppWhitelist: function () {
      return "No applications in the App Whitelist";
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
    IsAppWhitelistEnabled: function () {
      return this.$store.state.vpnState.splitTunnelling?.IsAppWhitelistEnabled;
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
};

function getFileName(appBinPath) {
  return appBinPath.split("\\").pop().split("/").pop();
}

function getFileFolder(appBinPath) {
  const fname = getFileName(appBinPath);
  return appBinPath.substring(0, appBinPath.length - fname.length);
}
</script>

<style scoped lang="scss">
@use "@/components/scss/constants";
@use "@/components/scss/platform/base.scss";

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
</style>
