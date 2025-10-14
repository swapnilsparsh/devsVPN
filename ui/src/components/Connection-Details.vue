<template>
  <div>
    <!-- Wireguard -->
    <div v-show="true" class="connectionDetailWrap">
      <div v-if="true">
        <!-- <div class="settingsBoldFont">Wireguard key information:</div> -->
        <div style="height: 5px"></div>
        <!-- <spinner :loading="isProcessing" /> -->
        <div class="flexRow paramBlockDetailedConfig">
          <div class="defColor paramName">Version:</div>
          <div class="detailedParamValue">
            {{ this.$store.state.daemonVersion }}
          </div>
        </div>

        <div class="flexRow paramBlockDetailedConfig">
          <div class="defColor paramName">OS:</div>
          <div class="detailedParamValue">
            {{ osVersionRelease }}
          </div>
        </div>

        <!-- <div class="flexRow paramBlockDetailedConfig">
          <div class="defColor paramName">Protocol:</div>
          <div class="detailedParamValue">
            {{ "Wireguard" }}
          </div>
        </div> -->
        <div class="flexRow paramBlockDetailedConfig">
          <div class="defColor paramName">Local IP Address:</div>
          <div class="detailedParamValue">
            {{ this.$store.state.account.session.WgLocalIP }}
          </div>
        </div>
        <!-- <div class="flexRow paramBlockDetailedConfig">
                    <div class="defColor paramName">Port:</div>
                    <div class="detailedParamValue">
                        {{ 'Port' }}
                    </div>
                </div> -->
        <div class="flexRow paramBlockDetailedConfig">
          <div class="defColor paramName">Public key:</div>
          <div class="detailedParamValue">
            {{ this.$store.state.account.session.WgPublicKey }}
          </div>
        </div>
        <div class="flexRow paramBlockDetailedConfig">
          <div class="defColor paramName">Generated:</div>
          <div class="detailedParamValue">
            {{ wgKeysGeneratedDateStr }}
          </div>
        </div>
        <!-- <div class="flexRow paramBlockDetailedConfig">
                    <div class="defColor paramName">Scheduled rotation date:</div>
                    <div class="detailedParamValue">
                        {{ wgKeysWillBeRegeneratedStr }}
                    </div>
                </div> -->
        <div class="flexRow paramBlockDetailedConfig">
          <div class="defColor paramName">Expiration date:</div>
          <div class="detailedParamValue">
            {{ wgKeysExpirationDateStr }}
          </div>
        </div>

        <!-- On Windows show always. On Linux show unless DISCONNECTED.
             This is because on Linux it's only possible to check VPN Coexistence state when the firewall is up.
             On Linux the firewall is enabled only when connected/connecting. Thus, when disconnected on Linux -
             not possible to check VPN Coexistence state.
          -->
        <div class="flexRow paramBlockDetailedConfig" v-if="showVpnCoex">
          <div class="defColor paramName">VPN Coexistence:</div>
          <div class="detailedParamValue">
            <div class="failedText" v-if="showVpnCoexFailed">
              <!-- TODO: WIll Fix Text Show According to the info received in this.$store.state.vpnState.firewallState ... -->
              FAILED
              <button class="retryBtn" @click="runVpnCoexistenceWizard" v-if="showVpnCoexFailedWithFixButton">
                Fix
              </button>
            </div>
            <div class="goodText" v-if="showVpnCoexGood">GOOD</div>
          </div>
        </div>

        <div
          v-if="this.$store.state.vpnState.connectionInfo !== null"
          class="flexRow paramBlockDetailedConfig"
        >
          <div class="defColor paramName">Transfer:</div>
          <!-- Sugestion: Blue for idle state and green for data exchanged -->
          <div
            :class="{
              greenBlinkingDot: isReceivedSendChanging,
              blueDot: !isReceivedSendChanging,
            }"
          ></div>
          <div class="detailedParamValue">
            {{ this.$store.state.vpnState.transferredData.ReceivedData }}
            received,
            {{ this.$store.state.vpnState.transferredData.SentData }} sent
          </div>
        </div>

        <div
          v-if="this.$store.state.vpnState.connectionInfo !== null"
          class="flexRow paramBlockDetailedConfig"
        >
          <div class="defColor paramName">Latest Handshake:</div>
          <div
            :class="{ greenBlinkingDot: isBlinking, greenDot: !isBlinking }"
          ></div>
          <div class="detailedParamValue">
            {{ formattedElapsedTime }}
          </div>
        </div>

        <div
          v-if="isDevRestApiBackend"
          class="flexRow paramBlockDetailedConfig"
        >
          <div class="defColor paramName">Network:</div>
          <div class="detailedParamValue">
            <div class="failedText">Development REST API servers</div>
          </div>
        </div>

        <!-- <div class="flexRow paramBlockDetailedConfig">
                    <div class="defColor paramName">Quantum Resistance:</div>
                    <div class="detailedParamValue">
                        {{ wgQuantumResistanceStr }}
                    </div>
                    <button class="noBordersBtn flexRow" title="Info"
                        v-on:click="this.$refs.infoWgQuantumResistance.showModal()">
                        <img src="@/assets/question.svg" />
                    </button>
                </div> -->
        <ComponentDialog ref="infoWgQuantumResistance" header="Info">
          <div>
            <p>
              Quantum Resistance: Indicates whether your current WireGuard VPN
              connection is using additional protection measures against
              potential future quantum computer attacks.
            </p>
            <p>
              When Enabled, a Pre-shared key has been securely exchanged between
              your device and the server using post-quantum Key Encapsulation
              Mechanism (KEM) algorithms. If Disabled, the current VPN
              connection, while secure under today's standards, does not include
              this extra layer of quantum resistance.
            </p>
          </div>
        </ComponentDialog>
      </div>
    </div>
  </div>
</template>

<script>
import { dateDefaultFormat } from "@/helpers/helpers";

import ComponentDialog from "@/components/component-dialog.vue";
import { Platform, PlatformEnum } from "@/platform/platform";

const sender = window.ipcSender;

export default {
  components: { ComponentDialog },
  props: ["isConnectedOrConnecting"],
  data: function () {
    return {
      isPortModified: false,
      isProcessing: false,
      openvpnManualConfig: false,
      startTime: null, // To keep track of when the stopwatch started
      elapsedTime: 0, // To keep track of elapsed time in seconds
      intervalId: null, // To store the interval ID for clearing it later
      isBlinking: false, // Control the blinking state
      blinkTimeout: null, // Store the timeout ID to stop blinking
      blinkTimeoutReceivedSend: null, // Store the timeout ID to stop blinking
      isReceivedSendChanging: false,
      vpnCoexistenceGood: false,
      isDevRestApiBackend: false,
    };
  },
  mounted() {
    this.vpnCoexistenceGood = this.weHaveTopFirewallPriority;
    this.isDevRestApiBackend = this.isDevRestApiBackendStore;

    // Parse the timestamp
    const ConnectedSince =
      this.$store.state.vpnState.connectionInfo?.ConnectedSince;
    if (ConnectedSince && ConnectedSince !== 0) {
      const parsedTime = new Date(ConnectedSince); // Parse the timestamp

      // Calculate the elapsed time in seconds
      const currentTime = Date.now();
      const elapsed = Math.floor((currentTime - parsedTime.getTime()) / 1000);

      this.elapsedTime = elapsed; // Set the timer to reflect elapsed time
      this.startTime = parsedTime.getTime(); // Start from the handshake time in milliseconds
      this.startStopwatch(); // Start the stopwatch
    }
  },
  watch: {
    // If port was changed in conneted state - reconnect
    async port(newValue, oldValue) {
      if (this.isPortModified === false) return;
      if (newValue == null || oldValue == null) return;
      if (newValue.port === oldValue.port && newValue.type === oldValue.type)
        return;
      await this.reconnect();
    },
    adjustedHandshakeTime(newValue, oldValue) {
      if (newValue === 0) {
        // Reset the stopwatch if adjustedHandshakeTime is 0
        this.resetStopwatch();
        this.isBlinking = false;
      } else {
        // Reset and restart the stopwatch if HandshakeTime changes and is not 0
        if (oldValue !== newValue) {
          this.resetStopwatch();
          this.startTime = Date.now();
          this.startStopwatch();
          this.triggerBlinking();
        }
      }
    },
    receivedData(newValue, oldValue) {
      this.checkReceivedSendChange(newValue, oldValue, "received");
    },
    sentData(newValue, oldValue) {
      this.checkReceivedSendChange(newValue, oldValue, "sent");
    },
    weHaveTopFirewallPriority() {
      this.vpnCoexistenceGood = this.weHaveTopFirewallPriority;
    },
    isDevRestApiBackendStore() {
      this.isDevRestApiBackend = this.isDevRestApiBackendStore;
    },
  },

  methods: {
    startStopwatch() {
      // Clear any existing interval to avoid multiple intervals running
      if (this.intervalId) {
        clearInterval(this.intervalId);
      }
      // Update elapsed time every second
      this.intervalId = setInterval(() => {
        this.elapsedTime = Math.floor((Date.now() - this.startTime) / 1000);
      }, 1000);
    },
    resetStopwatch() {
      // Stop the interval and reset the time
      if (this.intervalId) {
        clearInterval(this.intervalId);
        this.intervalId = null;
      }
      this.startTime = null;
      this.elapsedTime = 0;
    },
    triggerBlinking() {
      this.isBlinking = true;
      clearTimeout(this.blinkTimeout);
      this.blinkTimeout = setTimeout(() => {
        this.isBlinking = false;
      }, 500);
    },
    onWgKeyRegenerate: async function () {
      try {
        this.isProcessing = true;
        await sender.WgRegenerateKeys();
      } catch (e) {
        console.log(`ERROR: ${e}`);
        sender.showMessageBoxSync({
          type: "error",
          buttons: ["OK"],
          message: "Error generating WireGuard keys",
          detail: e,
        });
      } finally {
        this.isProcessing = false;
      }
    },
    getWgKeysGenerated: function () {
      if (
        this.$store.state.account == null ||
        this.$store.state.account.session == null ||
        this.$store.state.account.session.WgKeyGenerated == null
      )
        return null;
      return new Date(this.$store.state.account.session.WgKeyGenerated);
    },
    formatDate: function (d) {
      if (d == null) return null;
      return dateDefaultFormat(d);
    },
    checkReceivedSendChange(newValue, oldValue, type) {
      this.isReceivedSendChanging = false;
      if (newValue !== oldValue) {
        this.isReceivedSendChanging = true;
        // Stop blinking after a short period
        clearTimeout(this.blinkTimeoutReceivedSend);
        this.blinkTimeoutReceivedSend = setTimeout(() => {
          this.isReceivedSendChanging = false;
        }, 500);
      }
    },

    runVpnCoexistenceWizard() {
      //let shouldProceed = this.hasPermissionToReconfigureOtherVPNs;
      // let otherVpnsMsg = "";
      // if (this.$store.state.vpnState.firewallState.OtherVpnName && this.$store.state.vpnState.firewallState.OtherVpnName !== "") {
      //   otherVpnsMsg = this.$store.state.vpnState.firewallState.OtherVpnName;
      // } else if (this.$store.state.vpnState.firewallState.ReconfigurableOtherVpnsDetected) {
      //   otherVpnsMsg = this.$store.state.vpnState.firewallState.ReconfigurableOtherVpnsNames.toString();
      // }
      let introHeader = "privateLINE connectivity is blocked";
      let introDescr = "Other VPNs detected that may block our connectivity. It is necessary to reconfigure them. Press Next to continue.";

      // if (!shouldProceed) {
      //   let ret = await sender.showMessageBox(
      //     {
      //       type: "warning",
      //       buttons: ["OK", "Cancel"],
      //       message: "Please Confirm",
      //       detail: `Do you allow privateLINE to stop temporarily the other VPNs '${otherVpnsMsg}' and reconfigure them as needed for privateLINE connectivity? Press Ok to continue`,
      //       checkboxLabel: `Give PL Connect permission to reconfigure other VPNs automatically when needed (you can disable it in Settings later)`,
      //       checkboxChecked: false,
      //     },
      //     true
      //   );

      //   if (ret.response == 1) return; // cancel
      //   shouldProceed = (ret.response == 0);

      //   if (ret.checkboxChecked) {
      //     await sender.SetPermissionReconfigureOtherVPNs(true);
      //   }
      // }

      // if (shouldProceed) {
        let errMsg =
          "Error: failed to get top firewall permissions and/or reconfigure other VPNs - please disconnect PL Connect or stop the connection attempt, and retry VPN Coexistence wizard again.";
        try {
          sender.ShowVpnWizard(introHeader, introDescr, true, this.$store.state.vpnState.firewallState.NordVpnUpOnWindows, true, false);

          // let resp = await sender.KillSwitchReregister(true); // this will also kick off reconnection attempt
          // //console.log("resp", resp);
          // if (resp && resp !== null) {
          //   if (resp.OtherVpnUnknownToUs != null && resp.OtherVpnUnknownToUs) {
          //     errMsg =
          //       "Error: failed to get top firewall permissions - please take a screenshot or photo of this error message and email it to support@privateline.io";
          //     let detailMsg =
          //       `Error: ${resp.ErrorMessage}\n\n` +
          //       `Other VPN \'${resp.OtherVpnName}\' - \'${resp.OtherVpnGUID}\' is not registered in our database, we don't know how to stop it.\n\n` +
          //       "You can also try the following manual steps to try to allow PL Connect get the necessary top firewall permissions:\n\n" +
          //       "(1) Disconnect the other VPN and click Retry in PL Connect again. If successful - then reconnect to the other VPN.\n\n" +
          //       "(2) If previous step failed - stop the Windows service of the other VPN (via Services tab in Task Manager) and click Retry " +
          //       "in PL Connect again. If successful - then restart the service of the other VPN and reconnect to the other VPN.\n\n" +
          //       "(3) If previous step failed - uninstall the other VPN and click Retry in PL Connect again. Then reinstall the other VPN and reconnect to it.";
          //     sender.showMessageBoxSync({
          //       type: "error",
          //       buttons: ["OK"],
          //       message: errMsg,
          //       detail: detailMsg,
          //     });
          //   } else if (resp.ErrorMessage != null && resp.ErrorMessage) {
          //     console.error(resp.ErrorMessage);
          //     sender.showMessageBoxSync({
          //       type: "error",
          //       buttons: ["OK"],
          //       message: errMsg,
          //       detail: resp.ErrorMessage,
          //     });
          //   }
          // }

          // start connection attempt, as daemon disconnected VPN during KillSwitchReregister() call
          // await sender.Connect(); // Re-connect
        } catch (e) {
          console.error(e);
          sender.showMessageBoxSync({
            type: "error",
            buttons: ["OK"],
            message: errMsg,
            detail: e,
          });
          return;
        }
      // }
    },
  },
  computed: {
    osVersionRelease() {
      switch (Platform()) {
        case PlatformEnum.Windows:
        case PlatformEnum.macOS:
          return sender.osVersionRelease();
        case PlatformEnum.Linux:
          return this.$store.state.osVersion;
        default:
          return sender.osVersionRelease();
      }
    },
    adjustedHandshakeTime() {
      // Check if connectionInfo is null
      if (this.$store.state.vpnState.connectionInfo === null) {
        // Return 0 if the condition is true
        return 0;
      }
      // Otherwise, return the actual HandshakeTime
      return this.$store.state.vpnState.handshake.HandshakeTime;
    },
    weHaveTopFirewallPriority() {
      return this.$store.state.vpnState.firewallState.WeHaveTopFirewallPriority;
    },
    isDevRestApiBackendStore() {
      return this.$store.state.usingDevelopmentRestApiBackend;
    },
    formattedElapsedTime() {
      const minutes = Math.floor(this.elapsedTime / 60);
      const seconds = this.elapsedTime % 60;

      let result = "";
      if (minutes > 0) {
        result += `${minutes} minute${minutes > 1 ? "s" : ""}`;
      }
      if (seconds > 0) {
        if (result) {
          result += " ";
        }
        result += `${seconds} second${seconds > 1 ? "s" : ""}`;
      }
      return result || "0 seconds ago";
    },
    IsAccountActive: function () {
      // if no info about account status - let's believe that account is active
      if (
        !this.$store.state.account ||
        !this.$store.state.account.accountStatus
      )
        return true;
      return this.$store.state.account?.accountStatus?.Active === true;
    },
    wgKeyRegenerationInterval: {
      get() {
        return this.$store.state.account.session.WgKeysRegenIntervalSec;
      },
      set(value) {
        // daemon will send back a Hello response with updated 'session.WgKeysRegenIntervalSec'
        sender.WgSetKeysRotationInterval(value);
      },
    },

    wgKeysGeneratedDateStr: function () {
      return this.formatDate(this.getWgKeysGenerated());
    },
    wgKeysWillBeRegeneratedStr: function () {
      let t = this.getWgKeysGenerated();
      if (t == null) return null;

      t.setSeconds(
        t.getSeconds() +
          this.$store.state.account.session.WgKeysRegenIntervalSec
      );

      let now = new Date();
      if (t < now) {
        // Do not show planned regeneration date in the past (it can happen after the computer wake up from a long sleep)
        // Show 'today' as planned date to regenerate keys in this case.
        // (the max interval to check if regeneration required is defined on daemon side, it is less than 24 hours)
        t = now;
      }

      return this.formatDate(t);
    },
    wgKeysExpirationDateStr: function () {
      let t = this.getWgKeysGenerated();
      if (t == null) return null;
      t.setSeconds(t.getSeconds() + 40 * 24 * 60 * 60); // 40 days
      return this.formatDate(t);
    },
    wgRegenerationIntervals: function () {
      let ret = [{ text: "1 day", seconds: 24 * 60 * 60 }];
      for (let i = 2; i <= 30; i++) {
        ret.push({ text: `${i} days`, seconds: i * 24 * 60 * 60 });
      }
      return ret;
    },
    wgQuantumResistanceStr: function () {
      if (this.$store.state.account.session.WgUsePresharedKey === true)
        return "Enabled";
      return "Disabled";
    },
    receivedData() {
      return this.$store.state.vpnState.transferredData.ReceivedData;
    },
    sentData() {
      return this.$store.state.vpnState.transferredData.SentData;
    },
    isWindows: function () {
      return Platform() === PlatformEnum.Windows;
    },
    isLinux: function () {
      return Platform() === PlatformEnum.Linux;
    },
    isFirewallEnabled: function () {
      return this.$store.state.vpnState.firewallState.IsEnabled ?? false;
    },
    hasPermissionToReconfigureOtherVPNs: function () {
      return this.$store.state.settings?.daemonSettings?.PermissionReconfigureOtherVPNs ?? false;
    },
    /*
    // Firewall is down when disconnected, both Windows & Linux

    // One of the reasons for the below logic is - we don't want to show the Fix button to the user, while daemon is reconfiguring the firewall
    // and/or VPN coexistence. For example, when the firewall is down. This is so daemon doesn't receive repeat requests for reconfiguration.

    Linux:
      // on Linux VPN coexistence can be measured only when firewall is up,and it's up only when connected/connecting to the VPN
      !isConnectedOrConnecting																						                                        show	nothing

      isConnectedOrConnecting && isFirewallEnabled && vpnCoexistenceGood												                  show	VPN Coexistence: GOOD

      isConnectedOrConnecting && isFirewallEnabled && !vpnCoexistenceGood && hasPermissionToReconfigureOtherVPNs	show	VPN Coexistence: FAILED
      isConnectedOrConnecting && isFirewallEnabled && !vpnCoexistenceGood && !hasPermissionToReconfigureOtherVPNs	show	VPN Coexistence: FAILED | Fix

    Windows:
      vpnCoexistenceGood																								                                          show	VPN Coexistence: GOOD

      !isConnectedOrConnecting && !vpnCoexistenceGood && hasPermissionToReconfigureOtherVPNs						        	show	VPN Coexistence:
      !isConnectedOrConnecting && !vpnCoexistenceGood && !hasPermissionToReconfigureOtherVPNs							        show	VPN Coexistence: FAILED | Fix

      // on Windows NordVPN has to be manually reconfigured by user, even if daemon hasPermissionToReconfigureOtherVPNs - automatic logic can't reconfigure it yet
      isConnectedOrConnecting && isFirewallEnabled && !vpnCoexistenceGood                                       	show	VPN Coexistence: FAILED | Fix

    Windows and Linux, common:
      // means that reconfiguration is in progress
      isConnectedOrConnecting && !isFirewallEnabled																	                              show	VPN Coexistence:
    */
    showVpnCoex: function () {
      return this.isWindows || this.isConnectedOrConnecting;
    },
    showVpnCoexGood: function () {
      return this.vpnCoexistenceGood && (this.isWindows || (this.isConnectedOrConnecting && this.isFirewallEnabled));
    },
    showVpnCoexFailed: function () {
      if (this.vpnCoexistenceGood) return false;
      if (this.isConnectedOrConnecting)
        return this.isFirewallEnabled;
      else
        return (this.isWindows && !this.hasPermissionToReconfigureOtherVPNs);
    },
    showVpnCoexFailedWithFixButton: function () {
      if (this.vpnCoexistenceGood) return false;
      if (this.isConnectedOrConnecting)
        return (this.isFirewallEnabled && (this.isWindows || !this.hasPermissionToReconfigureOtherVPNs));
      else
        return (this.isWindows && !this.hasPermissionToReconfigureOtherVPNs);
    },
  },
};
</script>

<style scoped lang="scss">
@use "@/components/scss/constants";
@use "@/components/scss/platform/base";

.connectionDetailWrap {
  padding: 5px 20px 5px 20px;
}

div.detailedConfigParamBlock {
  @extend .flexRow;
  margin-top: 10px;
  width: 100%;
}

div.paramBlockDetailedConfig {
  gap: 5px;
}

div.detailedParamValue {
  font-weight: 600;
  overflow-wrap: break-word;
  -webkit-user-select: text;
  user-select: text;
  letter-spacing: 0.1px;
  overflow-wrap: anywhere;
  font-size: 11px;
  padding: 2px 0px 2px 0px;
}

div.paramName {
  color: var(--text-color-details);
  font-size: 12px;
  font-weight: 500;
}

div.greenDot {
  flex-shrink: 0;
  width: 11px;
  height: 11px;
  background-color: green;
  border-radius: 50%;
  margin-right: 10px;
}

div.blueDot {
  flex-shrink: 0;
  width: 11px;
  height: 11px;
  background-color: #449cf8;
  border-radius: 50%;
  margin-right: 10px;
}

div.greenBlinkingDot {
  flex-shrink: 0;
  width: 11px;
  height: 11px;
  margin-right: 10px;
  background-color: green;
  border-radius: 50%;
  animation: blink 0.5s infinite;
}

@keyframes blink {
  0% {
    opacity: 1;
  }

  50% {
    opacity: 0;
  }

  100% {
    opacity: 1;
  }
}

.retryBtn {
  font-size: 11px;
  font-weight: 500;
  // color: #6c757d;
  // background-color: transparent;
  // border: 1px solid #6c757d;
  color: #495057;
  border-color: #495057;
  background-color: #f8f9fa;
  padding: 4px 8px;
  border-radius: 4px;
  cursor: pointer;
  transition: all 0.2s ease-in-out;
}

.retryBtn:hover {
  color: #495057;
  border-color: #495057;
  background-color: #f8f9fa;
}

.failedText {
  color: rgb(251, 24, 24);
  font-weight: bold;
}

.goodText {
  color: rgb(34, 237, 34);
  font-weight: bold;
}
</style>
