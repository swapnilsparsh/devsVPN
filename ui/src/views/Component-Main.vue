<template>
  <div id="flexview">
    <div class="flexColumn">
      <div class="leftPanelTopSpace">
        <transition name="smooth-display">
          <div
            class="minimizedButtonsPanel leftPanelTopMinimizedButtonsPanel"
            v-bind:class="{
              minimizedButtonsPanelRightElements: isWindowHasFrame,
            }"
          >
            <button
              v-if="isLoggedIn"
              @click="onAccountSettings"
              title="Menu"
              class="menu-button"
            >
              <img src="@/assets/menu.svg" />
            </button>

            <button
              v-if="!isLoggedIn"
              @click="onSettings"
              title="Menu"
              class="menu-button"
            >
              <img src="@/assets/menu.svg" />
            </button>

            <!-- <button
              v-if="isLoggedIn"
              @click="toggleMenu"
              title="Menu"
              class="menu-button"
            >
              <img src="@/assets/menu.svg" />
            </button> -->

            <div v-if="isMenuVisible" class="menu">
              <button
                @click="onAccountSettings"
                title="Account settings"
                class="menu-item"
                style="margin: 0; padding: 3px 5px"
              >
                <img src="@/assets/user.svg" />
                Account
              </button>

              <button
                @click="onSettings"
                title="Settings"
                class="menu-item"
                style="margin: 0; padding: 3px 5px"
              >
                <img src="@/assets/settings.svg" />
                Settings
              </button>
            </div>
            <button v-on:click="onPrivateLine()" title="privateLINE">
              <img
                src="@/assets/logo.png"
                style="
                  width: 22px;
                  height: 22px;
                  pointer-events: none;
                  border: 2px solid #fff;
                  border-radius: 8px;
                "
              />
            </button>
            <div style="color: #fff; font-weight: 500">privateLINE Connect</div>

            <!-- <button v-on:click="onMaximize(true)" title="Show map">
              <img src="@/assets/maximize.svg" />
            </button> -->
          </div>
        </transition>
      </div>
      <div class="flexColumn" style="min-height: 0px; height: 92vh">
        <transition name="fade" mode="out-in">
          <component
            v-bind:is="currentViewComponent"
            :onConnectionSettings="onConnectionSettings"
            :onWifiSettings="onWifiSettings"
            :onFirewallSettings="onFirewallSettings"
            :onAntiTrackerSettings="onAntitrackerSettings"
            :onDefaultView="onDefaultLeftView"
            id="left"
          ></component>
        </transition>
      </div>
    </div>
    <div id="right" v-if="!isMinimizedUI">
      <transition name="fade" appear>
        <TheMap
          :isBlured="isMapBlured"
          :onAccountSettings="onAccountSettings"
          :onSettings="onSettings"
          :onMinimize="() => onMaximize(false)"
        />
      </transition>
    </div>
  </div>
</template>

<script>
const sender = window.ipcSender;

import { DaemonConnectionType } from "@/store/types";
import { IsWindowHasFrame } from "@/platform/platform";
import Init from "@/components/Component-Init.vue";
import Login from "@/components/Component-Login.vue";
import Control from "@/components/Component-Control.vue";
import TheMap from "@/components/Component-Map.vue";
import ParanoidModePassword from "@/components/ParanoidModePassword.vue";

export default {
  components: {
    Init,
    Login,
    Control,
    TheMap,
    ParanoidModePassword,
  },
  data: function () {
    return {
      isCanShowMinimizedButtons: true,
      isMenuVisible: false,
    };
  },
  computed: {
    isWindowHasFrame: function () {
      return IsWindowHasFrame();
    },
    isLoggedIn: function () {
      return this.$store.getters["account/isLoggedIn"];
    },
    currentViewComponent: function () {
      this.$store.dispatch("settings/minimizedUI", true);

      const daemonConnection = this.$store.state.daemonConnectionState;
      if (
        daemonConnection == null ||
        daemonConnection === DaemonConnectionType.NotConnected ||
        daemonConnection === DaemonConnectionType.Connecting
      )
        return Init;
      if (this.$store.state.uiState.isParanoidModePasswordView === true)
        return ParanoidModePassword;
      if (!this.isLoggedIn) return Login;

      return Control;
    },
    isMapBlured: function () {
      if (this.currentViewComponent !== Control) return "true";
      return "false";
    },
    isMinimizedButtonsVisible: function () {
      if (this.currentViewComponent !== Control) return false;
      if (this.isCanShowMinimizedButtons !== true) return false;
      return this.isMinimizedUI;
    },
    isMinimizedUI: function () {
      return this.$store.state.settings.minimizedUI;
    },
  },

  watch: {
    isLoggedIn(newValue) {
      if (!newValue) {
        this.isMenuVisible = false;
      }
    },
  },

  methods: {
    onPrivateLine: function () {
      sender.shellOpenExternal(`https://privateline.io/`);
    },
    toggleMenu() {
      this.isMenuVisible = !this.isMenuVisible;
    },
    onAccountSettings: function () {
      //if (this.$store.state.settings.minimizedUI)
      sender.ShowAccountSettings();
      this.isMenuVisible = false;
      //else this.$router.push({ name: "settings", params: { view: "account" } });
    },
    onSettings: function () {
      sender.ShowSettings();
      this.isMenuVisible = false;
    },
    onConnectionSettings: function () {
      sender.ShowConnectionSettings();
    },
    onWifiSettings: function () {
      sender.ShowWifiSettings();
    },
    onFirewallSettings: function () {
      sender.ShowFirewallSettings();
    },
    onAntitrackerSettings: function () {
      sender.ShowAntitrackerSettings();
    },
    onDefaultLeftView: function (isDefaultView) {
      this.isCanShowMinimizedButtons = isDefaultView;
    },
    onMaximize: function (isMaximize) {
      this.$store.dispatch("settings/minimizedUI", !isMaximize);
    },
  },
};
</script>

<style scoped lang="scss">
@use "@/components/scss/constants";

// #flexview {
//   display: flex;
//   flex-direction: row;
//   height: 100%;
// }

// #left {
//   width: 320px;
//   min-width: 320px;
//   max-width: 320px;
// }
#right {
  width: 0%; // ???
  flex-grow: 1;
}

div.minimizedButtonsPanelRightElements {
  display: flex;
  justify-content: flex-end;
}

div.minimizedButtonsPanel {
  display: flex;
  background-color: #6f329d;
  padding: 10px;
}

div.minimizedButtonsPanel button {
  @extend .noBordersBtn;

  -webkit-app-region: no-drag;
  z-index: 101;
  cursor: pointer;

  padding: 0px;
  margin-left: 6px;
  margin-right: 6px;
}

div.minimizedButtonsPanel img {
  height: 18px;
}

.menu-container {
  position: relative;
}

.menu-button {
  position: relative;
  background: none;
  border: none;
  cursor: pointer;
  display: flex;
  align-items: center;
}

.menu {
  position: absolute;
  top: 6%;
  left: 6%;
  border: 1px solid #cccccc;
  border-radius: 4px;
  z-index: 1000;
  display: flex;
  flex-direction: column;
  gap: 6px;
  padding: 5px;
}

.menu-item {
  display: flex;
  align-items: center;
  border: none;
  background: none;
  cursor: pointer;
}

.menu-item img {
  margin-right: 8px;
}
</style>
