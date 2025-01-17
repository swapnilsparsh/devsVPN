<template>
  <div class="flexColumn">
    <transition name="fade-super-quick" mode="out-in">
      <div
        class="flexColumn"
        v-if="uiView === 'serversEntry'"
        key="entryServers"
      >
        <Servers
          :onBack="backToMainView"
          :onServerChanged="onServerChanged"
          :onFastestServer="onFastestServer"
          :onRandomServer="onRandomServer"
        />
      </div>

      <div
        class="flexColumn"
        v-else-if="uiView === 'serversExit'"
        key="exitServers"
      >
        <Servers
          :onBack="backToMainView"
          isExitServer="true"
          :onServerChanged="onServerChanged"
          :onRandomServer="() => onRandomServer(true)"
        />
      </div>

      <div v-else class="flexColumn">
        <div>
          <ConnectBlock
            :onChecked="switchChecked"
            :isChecked="isConnected"
            :isProgress="isInProgress"
            :onPauseResume="onPauseResume"
          />
          <!-- <div class="horizontalLine shieldButtonsSeparator" /> -->
        </div>

        <div
          ref="scrollArea"
          class="scrollableColumnContainer"
          @scroll="recalcScrollButtonVisiblity()"
        >
          <!-- <div v-if="isMultihopAllowed">
            <HopButtonsBlock />
            <div class="horizontalLine hopButtonsSeparator" />
          </div> -->
          <!-- ============ TODOC2: Shield and Full Shield Button ================ -->
          <div>
            <ShieldButtonsBlock />
            <div class="horizontalLine shieldButtonsSeparator" />
          </div>

          <SelectedServerBlock :onShowServersPressed="onShowServersPressed" />

          <div v-if="this.$store.state.settings.isMultiHop">
            <div class="horizontalLine" />
            <SelectedServerBlock
              :onShowServersPressed="onShowServersPressed"
              isExitServer="true"
            />
          </div>

          <ConnectionDetailsBlock
            :onShowPorts="onShowPorts"
            :onShowWifiConfig="onShowWifiConfig"
            :onShowFirewallConfig="onFirewallSettings"
            :onShowAntiTrackerConfig="onAntiTrackerSettings"
          />
          <ConnectionDetails />

          <transition name="fade">
            <button
              class="btnScrollDown"
              v-if="isShowScrollButton"
              v-on:click="onScrollDown()"
            >
              <img src="@/assets/arrow-bottom.svg" />
            </button>
          </transition>
        </div>

        <FooterBlock/>
      </div>
    </transition>
  </div>
</template>

<script>
import Servers from "./Component-Servers.vue";
import ConnectBlock from "./blocks/block-connect.vue";
import ConnectionDetailsBlock from "./blocks/block-connection-details.vue";
import SelectedServerBlock from "@/components/blocks/block-selected-server.vue";
import HopButtonsBlock from "./blocks/block-hop-buttons.vue";
import ShieldButtonsBlock from "./blocks/block-shield-buttons.vue/";
import ConnectionDetails from "./Connection-Details.vue";
import FooterBlock from "./blocks/block-footer.vue";
import { getDaysDifference } from "../helpers/renderer.js";

const sender = window.ipcSender;
import { VpnStateEnum, VpnTypeEnum } from "@/store/types";
import { capitalizeFirstLetter } from "@/helpers/helpers";

const viewTypeEnum = Object.freeze({
  default: "default",
  serversEntry: "serversEntry",
  serversExit: "serversExit",
});

async function connect(me, isConnect) {
  try {
    me.isConnectProgress = true;
    if (isConnect === true) {
      let expired = false;
      const subscriptionData = me.$store.state.account.subscriptionData;

      if (
        subscriptionData && subscriptionData !== null && 
        subscriptionData.Plan && subscriptionData.Plan != null &&
        subscriptionData.Plan.name && subscriptionData.Plan.name != null
      ) {
        if (
          subscriptionData.Plan.name !== "Free" &&
          getDaysDifference(subscriptionData.expire_on) <= 0
        ) {
          expired = true;
        }
      }

      if (!expired) {
        await sender.Connect();
      } else {
        const result = sender.showMessageBoxSync({
          type: "error",
          buttons: ["Buy new plan"],
          message: "Can't connect. Your subscription has expired",
        });

        if (result === 0) {
          sender.shellOpenExternal(`https://privateline.io/#pricing`);
        }
        return;
      }
    } else {
      await sender.Disconnect();
    }
  } catch (e) {
    console.error(e);
    sender.showMessageBoxSync({
      type: "error",
      buttons: ["OK"],
      message: `Failed to ${isConnect ? "connect" : "disconnect"}: ` + e,
    });
  } finally {
    me.isConnectProgress = false;
  }
}

export default {
  props: {
    onConnectionSettings: Function,
    onWifiSettings: Function,
    onFirewallSettings: Function,
    onAntiTrackerSettings: Function,
    onDefaultView: Function,
  },

  components: {
    HopButtonsBlock,
    Servers,
    ConnectBlock,
    SelectedServerBlock,
    ConnectionDetailsBlock,
    ShieldButtonsBlock,
    ConnectionDetails,
    FooterBlock,
  },
  mounted() {
    this.recalcScrollButtonVisiblity();

    // ResizeObserver sometimes is stopping to work for unknown reason. So, We do not use it for now
    // Instead, watchers are in use: isMinimizedUI, isMultiHop
    //const resizeObserver = new ResizeObserver(this.recalcScrollButtonVisiblity);
    //resizeObserver.observe(this.$refs.scrollArea);

    if (!this.IsAccIdLogin)
        this.PromptToMigrateSsoUser();
  },
  data: function () {
    return {
      isShowScrollButton: false,
      isConnectProgress: false,
      uiView: viewTypeEnum.default,
      lastServersPingRequestTime: null,
    };
  },

  computed: {
    isConnected: function () {
      return this.$store.getters["vpnState/isConnected"];
    },
    isConnecting: function () {
      return this.$store.getters["vpnState/isConnecting"];
    },
    isOpenVPN: function () {
      return this.$store.state.settings.vpnType === VpnTypeEnum.OpenVPN;
    },
    isMultihopAllowed: function () {
      return this.$store.getters["account/isMultihopAllowed"];
    },
    isInProgress: function () {
      if (this.isConnectProgress) return this.isConnectProgress;
      return (
        this.$store.state.vpnState.connectionState !== VpnStateEnum.CONNECTED &&
        this.$store.state.vpnState.connectionState !== VpnStateEnum.DISCONNECTED
      );
    },
    // needed for watcher
    conectionState: function () {
      return this.$store.state.vpnState.connectionState;
    },
    isMinimizedUI: function () {
      return this.$store.state.settings.minimizedUI;
    },
    isMultiHop: function () {
      return this.$store.state.settings.isMultiHop;
    },
    IsSessionInfoReceived: function () {
      return this.$store.state.account.session.SessionInfoReceived;
    },
    IsAccIdLogin: function () {
      let value = false;

      if (
        this.IsSessionInfoReceived &&
        this.$store.state.account != null &&
        this.$store.state.account.session != null &&
        this.$store.state.account.session.AccountID != null &&
        this.$store.state.account.session.AccountID !== ""
      ) {
        const accountId = this.$store.state.account.session.AccountID;
        // Check if accountId matches the pattern XXXX-XXXX-XXXX. Characters '0', 'O', 'I' are forbidden.
        const accountIdPattern = /^(a-)?([1-9A-HJ-NP-Z]{4}-){2}[1-9A-HJ-NP-Z]{4}$/;
        value = accountIdPattern.test(accountId);
      }

      return value;
    },
  },

  watch: {
    conectionState(newValue, oldValue) {
      // show connection failure description:

      // only in case of changing to DISCONNECTED
      if (newValue !== VpnStateEnum.DISCONNECTED || newValue == oldValue)
        return;

      // if disconnection reason defined
      let failureInfo = this.$store.state.vpnState.disconnectedInfo;
      if (!failureInfo || !failureInfo.ReasonDescription) return;

      sender.showMessageBoxSync({
        type: "error",
        buttons: ["OK"],
        message: `Failed to connect`,
        detail: capitalizeFirstLetter(failureInfo.ReasonDescription),
      });
    },
    isMinimizedUI() {
      setTimeout(() => this.recalcScrollButtonVisiblity(), 1000);
    },
    isMultiHop() {
      setTimeout(() => this.recalcScrollButtonVisiblity(), 1000);
    },
    // IsAccIdLogin() {
    //   if (!this.IsAccIdLogin)
    //     this.PromptToMigrateSsoUser();
    // },
  },

  methods: {
    async switchChecked(isConnect) {
      connect(this, isConnect);
    },
    async onPauseResume(seconds) {
      if (seconds == null || seconds == 0) {
        // RESUME
        if (this.$store.getters["vpnState/isPaused"])
          await sender.ResumeConnection();
      } else {
        // PAUSE
        await sender.PauseConnection(seconds);
      }
    },
    async onShowServersPressed(isExitServers) {
      // send request to update servers from backend
      sender.UpdateServersRequest();

      this.uiView = isExitServers
        ? viewTypeEnum.serversExit
        : viewTypeEnum.serversEntry;

      if (this.onDefaultView) this.onDefaultView(false);

      // request servers ping not more often than once per 15 seconds
      let isHasPingResuls =
        Object.keys(this.$store.state.vpnState.hostsPings).length > 0;
      if (
        isHasPingResuls == false ||
        this.lastServersPingRequestTime == null ||
        (new Date().getTime() - this.lastServersPingRequestTime.getTime()) /
          1000 >
          15
      ) {
        try {
          await sender.PingServers();
        } catch (e) {
          console.error(e);
        }
        this.lastServersPingRequestTime = new Date();
      } else {
        console.log(
          "Server pings request blocked (due to requests per minute limitation)"
        );
      }
    },
    onShowPorts() {
      if (this.onConnectionSettings != null) this.onConnectionSettings();
    },
    onShowWifiConfig() {
      if (this.onWifiSettings != null) this.onWifiSettings();
    },
    backToMainView() {
      this.uiView = viewTypeEnum.default;
      if (this.onDefaultView) this.onDefaultView(true);

      setTimeout(this.recalcScrollButtonVisiblity, 1000);
    },
    onServerChanged(server, isExitServer, serverHostName) {
      if (server == null || isExitServer == null) return;
      let hostId = null;
      if (serverHostName) {
        // serverHostName - not null when user selected specific host of the server
        hostId = serverHostName.split(".")[0];
      }

      let needReconnect = false;
      if (!isExitServer) {
        if (
          !this.$store.state.settings.serverEntry ||
          this.$store.state.settings.serverEntry.gateway !== server.gateway ||
          this.$store.state.settings.serverEntryHostId !== hostId ||
          this.$store.state.settings.isRandomServer !== false
        ) {
          this.$store.dispatch("settings/isRandomServer", false);
          this.$store.dispatch("settings/serverEntry", server);
          this.$store.dispatch("settings/serverEntryHostId", hostId);
          needReconnect = true;
        }
      } else {
        if (
          !this.$store.state.settings.serverExit ||
          this.$store.state.settings.serverExit.gateway !== server.gateway ||
          this.$store.state.settings.serverExitHostId !== hostId ||
          this.$store.state.settings.isRandomExitServer !== false
        ) {
          this.$store.dispatch("settings/isRandomExitServer", false);
          this.$store.dispatch("settings/serverExit", server);
          this.$store.dispatch("settings/serverExitHostId", hostId);
          needReconnect = true;
        }
      }
      if (this.$store.state.settings.isFastestServer !== false) {
        this.$store.dispatch("settings/isFastestServer", false);
        needReconnect = true;
      }

      if (needReconnect == true && (this.isConnecting || this.isConnected))
        connect(this, true);
    },
    onFastestServer() {
      this.$store.dispatch("settings/isFastestServer", true);
      if (this.isConnected) connect(this, true);
    },
    onRandomServer(isExitServer) {
      if (isExitServer === true)
        this.$store.dispatch("settings/isRandomExitServer", true);
      else this.$store.dispatch("settings/isRandomServer", true);
      if (this.isConnected) connect(this, true);
    },
    recalcScrollButtonVisiblity() {
      let sa = this.$refs.scrollArea;
      if (sa == null) {
        this.isShowScrollButton = false;
        return;
      }

      const isNeedToShow = function () {
        let pixelsToTheEndScroll =
          sa.scrollHeight - (sa.clientHeight + sa.scrollTop);
        // hide if the 'pixels to scroll' < 20
        if (pixelsToTheEndScroll < 20) return false;
        return true;
      };

      // hide - imediately; show - with 1sec delay
      if (!isNeedToShow()) this.isShowScrollButton = false;
      else {
        setTimeout(() => {
          this.isShowScrollButton = isNeedToShow();
        }, 1000);
      }
    },
    onScrollDown() {
      let sa = this.$refs.scrollArea;
      if (sa == null) return;
      sa.scrollTo({
        top: sa.scrollHeight,
        behavior: "smooth",
      });
    },

    async PromptToMigrateSsoUser() {
      try {
        console.log("entered PromptToMigrateSsoUser()");
        if (this.IsAccIdLogin)
          return; // nothing to do

        // Handle migration of SSO accounts to account ID
        const result = sender.showMessageBoxSync({
          type: "info",
          buttons: ["Migrate", "Do it later!"],
          message: "Account Migration Notice",
          detail: "We have migrated to a new login system supporting anonymous accounts. You can either migrate your account to the new system or continue using your existing SSO account.\n\n" +
                  "With the new login system, your account will be converted to an anonymous account. Anonymous accounts do not require us to collect your email, phone number, or any other personal details, not even your name, ensuring a more private experience.\n\n" +
                  "Concerned about your existing data? Rest assured, all your plan details, tunnels, and other information will remain completely safe and unchanged during the migration process. The only change will be to your account ID, which will be used solely for login — no password required.\n\n" +
                  "Take this step today and enjoy a seamless, personalized experience tailored just for you!"
        });

        if (result === 1)
          return; // user cancelled

        const resp = await sender.MigrateSsoUser()
        if (resp.APIStatus !== 200 || resp.APIErrorMessage != "") { // error migrating
          sender.showMessageBoxSync({
            type: "error",
            buttons: ["OK"],
            message: "Failed to migrate SSO account",
            detail:
              resp.APIStatus + ": " + resp.APIErrorMessage +
              "\n\nPlease login to your account at https://account.privateline.io and finish the migration process there.",
          });
        } else { // we're good, SSO account successfully migrated to account ID
          sender.showMessageBoxSync({
            type: "info",
            buttons: ["OK"],
            message: "Account Migrated Successfully",
            detail: `Your Account ID: ${resp.AccountID}. You can also view it under Settings/Account\n\n` + 
                    "For future logins, simply use your account ID — no password needed.\n\n" + 
                    "Please save the account ID and keep it secure — it's your sole identifier for using our service. No email or username is required, ensuring your anonymity. Do not share your account ID with anyone.",
          });
        }
      } catch (e) {
        console.error(e);
        sender.showMessageBoxSync({
          type: "error",
          buttons: ["OK"],
          message: "Failed to migrate SSO account",
          detail: `${e}` +
            "\n\nPlease login to your account at https://account.privateline.io and finish the migration process there.",
        });
      }
    },
  },
};
</script>

<!-- Add "scoped" attribute to limit CSS to this component only -->
<style scoped lang="scss">
@import "@/components/scss/constants";
</style>
