<template>
  <transition name="fade-quick" appear>
    <div id="main" class="row">
      <div id="leftPanel" class="settingsLeftPanel">
        <div class="flexColumn">
          <div
            class="row settingsLeftPanelHeader"
            style="flex-wrap: wrap"
            id="leftPanelHeader"
          >
            <button id="backBtn" class="noBordersBtn" v-on:click="goBack">
              <!-- ARROW LEFT -->
              <settingsImgArrowLeft />
            </button>
            <!-- ========== TODOC1: Setting ============ -->
            <!-- <div class="Header settingsHeader">Settings</div> -->
            <img
              width="70%"
              style="pointer-events: none"
              src="@/assets/white-logo.png"
            />
            <hr
              style="
                width: 100%;
                margin-top: 15px;
                border: none;
                border-top: 1px solid #ccc;
                flex-basis: 85%;
              "
            />
          </div>

          <!-- TABS -->
          <div class="row" style="flex-grow: 1">
            <div id="tabsTitle">
              <button
                v-if="isLoggedIn"
                class="noBordersBtn tabTitleBtn"
                v-on:click="onView('account')"
                v-bind:class="{
                  activeBtn: view === 'account',
                }"
              >
                <img
                  style="width: 18px; height: 18px"
                  src="@/assets/settings-account.svg"
                />
                Account
              </button>

              <button
                class="noBordersBtn tabTitleBtn"
                v-on:click="onView('general')"
                v-bind:class="{
                  activeBtn: view === 'general',
                }"
              >
                <img
                  style="width: 18px; height: 18px"
                  src="@/assets/settings-general.svg"
                />
                General
              </button>

              <button
                v-if="isLoggedIn"
                class="noBordersBtn tabTitleBtn"
                v-on:click="onView('connection')"
                v-bind:class="{
                  activeBtn: view === 'connection',
                }"
              >
                <img
                  style="width: 18px; height: 18px"
                  src="@/assets/settings-connection.svg"
                />
                Connection
              </button>
              <button
                v-if="isLoggedIn"
                class="noBordersBtn tabTitleBtn"
                v-on:click="onView('manageDevice')"
                v-bind:class="{
                  activeBtn: view === 'manageDevice',
                }"
              >
                <img
                  style="width: 18px; height: 18px"
                  src="@/assets/settings-whitelist.svg"
                />
                Manage Devices
              </button>
              <!-- <button
                v-if="isLoggedIn"
                class="noBordersBtn tabTitleBtn"
                v-on:click="onView('firewall')"
                v-bind:class="{
                  activeBtn: view === 'firewall',
                }"
              >
                PrivateLINE Firewall
              </button> -->
              
              <!-- Vlad: disabling App Whitelist for now
              <button
                v-if="isLinux && isLoggedIn"
                class="noBordersBtn tabTitleBtn"
                v-on:click="onView('appwhitelist')"
                v-bind:class="{
                  activeBtn: view === 'appwhitelist',
                }"
              >
                <img
                  style="width: 18px; height: 18px"
                  src="@/assets/settings-whitelist.svg"
                />
                App Whitelist
              </button>
              -->

              <!-- <button
                v-if="isLoggedIn"
                class="noBordersBtn tabTitleBtn"
                v-on:click="onView('networks')"
                v-bind:class="{
                  activeBtn: view === 'networks',
                }"
              >
                Wi-Fi control
              </button> -->

              <!-- <button
                v-if="isLoggedIn"
                class="noBordersBtn tabTitleBtn"
                v-on:click="onView('antitracker')"
                v-bind:class="{
                  activeBtn: view === 'antitracker',
                }"
              >
                AntiTracker
              </button> -->
              <!-- <button
                v-if="isLoggedIn"
                class="noBordersBtn tabTitleBtn"
                v-on:click="onView('dns')"
                v-bind:class="{
                  activeBtn: view === 'dns',
                }"
              >
                DNS
              </button> -->

              <!-- <button
                v-if="isLoggedIn"
                class="noBordersBtn tabTitleBtn"
                v-on:click="onView('advanced')"
                v-bind:class="{
                  activeBtn: view === 'advanced',
                }"
              >
                Advanced
              </button> -->

              <!--
          <button
            class="noBordersBtn tabTitleBtn"
            v-on:click="onView('openvpn')"
            v-bind:class="{
              activeBtn: view === 'openvpn'
            }"
          >
            OpenVPN
          </button>
          -->
            </div>
          </div>

          <!-- VERSION -->
          <div class="flexRow" style="flex-grow: 1">
            <div class="flexRow" style="margin-left: 30px; flex-grow: 1">
              <VersionBlock />
            </div>
          </div>
        </div>
      </div>

      <div class="rightPanel">
        <div class="flexColumn" v-if="view === 'connection'">
          <connectionView />
        </div>
        <div class="flexColumn" v-else-if="view === 'account'">
          <accountView />
        </div>
        <div class="flexColumn" v-else-if="view === 'manageDevice'">
          <manageDevice />
        </div>
        <div class="flexColumn" v-else-if="view === 'general'">
          <generalView />
        </div>
        <div class="flexColumn" v-else-if="view === 'firewall'">
          <firewallView
            :registerBeforeCloseHandler="doRegisterBeforeViewCloseHandler"
          />
        </div>
        <div class="flexColumn" v-else-if="view === 'appwhitelist'">
          <appWhitelistView />
        </div>
        <div class="flexColumn" v-else-if="view === 'networks'">
          <networksView />
        </div>
        <div class="flexColumn" v-else-if="view === 'antitracker'">
          <antitrackerView />
        </div>
        <div class="flexColumn" v-else-if="view === 'dns'">
          <dnsView
            :registerBeforeCloseHandler="doRegisterBeforeViewCloseHandler"
          />
        </div>
        <div class="flexColumn" v-else-if="view === 'advanced'">
          <advancedView />
        </div>
        <div class="flexColumn" v-else>
          <!-- no view defined -->
        </div>
      </div>
    </div>
  </transition>
</template>

<script>
const sender = window.ipcSender;

import { Platform, PlatformEnum } from "@/platform/platform";

import connectionView from "@/components/settings/settings-connection.vue";
import accountView from "@/components/settings/settings-account.vue";
import manageDevice from "@/components/settings/settings-manage-device.vue";
import generalView from "@/components/settings/settings-general.vue";
import firewallView from "@/components/settings/settings-firewall.vue";
import appWhitelistView from "@/components/settings/settings-appwhitelist.vue";
import networksView from "@/components/settings/settings-networks.vue";
import antitrackerView from "@/components/settings/settings-antitracker.vue";
import dnsView from "@/components/settings/settings-dns.vue";
import advancedView from "@/components/settings/settings-advanced.vue";
import VersionBlock from "@/components/blocks/block-version.vue";

import settingsImgArrowLeft from "@/components/images/settings-arrow-left.vue";

export default {
  components: {
    connectionView,
    accountView,
    manageDevice,
    generalView,
    firewallView,
    appWhitelistView,
    networksView,
    antitrackerView,
    dnsView,
    advancedView,
    settingsImgArrowLeft,
    VersionBlock,
  },
  mounted() {
    this.onBeforeViewCloseHandler = null;
    if (this.$route.params.view != null) this.view = this.$route.params.view;
    this.$store.dispatch("uiState/currentSettingsViewName", this.view);
  },
  data: function () {
    return {
      view: "general",
      // Handler which will be called before closing current view (null - in case if no handler registered for current view).
      // Handler MUST be 'async' function and MUST return 'true' to allow to switch current view
      onBeforeViewCloseHandler: Function,
    };
  },
  computed: {
    isLoggedIn: function () {
      return this.$store.getters["account/isLoggedIn"];
    },
    isLinux: function () {
      return Platform() === PlatformEnum.Linux;
    },
    isSplitTunnelVisible() {
      return this.$store.getters["isSplitTunnelEnabled"];
    },
  },
  methods: {
    goBack: async function () {
      if (this.$store.state.settings.minimizedUI) {
        sender.closeCurrentWindow();
      } else {
        // Call async 'BeforeViewCloseHandler' for current view (if exists). Block view change if handler return != true
        if (this.onBeforeViewCloseHandler != null) {
          if ((await this.onBeforeViewCloseHandler()) != true) return;
        }

        this.$router.push("/");
      }

      this.onBeforeViewCloseHandler = null; // forget 'onBeforeViewCloseHandler' for current view
      this.$store.dispatch("uiState/currentSettingsViewName", null);
    },
    onView: async function (viewName) {
      // Call async 'BeforeViewCloseHandler' for current view (if exists). Block view change if handler return != true
      if (this.onBeforeViewCloseHandler != null) {
        if ((await this.onBeforeViewCloseHandler()) != true) return;
      }

      this.onBeforeViewCloseHandler = null; // forget 'onBeforeViewCloseHandler' for current view
      this.view = viewName;
      this.$store.dispatch("uiState/currentSettingsViewName", this.view);
    },
    doRegisterBeforeViewCloseHandler: function (handler) {
      // Register handler which will be called before closing current view
      // Handler MUST be 'async' function and MUST return 'true' to allow to switch current view
      this.onBeforeViewCloseHandler = handler;
    },
  },
};
</script>

<style scoped lang="scss">
@use "@/components/scss/constants";

$back-btn-width: 50px;
$min-title-height: 26px;

div.row {
  display: flex;
  flex-direction: row;
  width: 100%;
}

#main {
  height: 100%;

  font-size: 13px;
  line-height: 16px;
  letter-spacing: -0.58px;
}
#leftPanel {
  padding-top: 50px;
  background: #6f329d;
  min-width: 232px;
  max-width: 232px;
  height: 100vh;
}
#leftPanelHeader {
  padding-bottom: 23px;
}
#tabsTitle {
  width: 100%;

  display: flex;
  flex-flow: column;
  overflow: auto;

  margin-left: 30px;
}
.rightPanel {
  margin-top: 58px;
  margin-left: 34px;
  margin-right: 51px;
  margin-bottom: 20px;

  width: 100vw;
}

.rightPanel * {
  @extend .settingsDefaultText;
}

#backBtn {
  min-width: $back-btn-width;
  max-width: $back-btn-width;

  display: flex;
  justify-content: center;
  align-items: center;
}

.Header {
  font-style: normal;
  font-weight: 800;
  font-size: 24px;
  line-height: 29px;

  letter-spacing: -0.3px;
  text-transform: capitalize;
}

button.noBordersBtn {
  border: none;
  background-color: inherit;
  outline-width: 0;
  cursor: pointer;
  width: fit-content;
}
button.tabTitleBtn {
  display: flex;
  padding: 0px;
  gap: 5px;

  margin-bottom: 19px;

  font-size: 16px;
  line-height: 17px;

  color: #fff;
}
button.activeBtn {
  font-weight: 600;
  color: #fff;
}
</style>
