<template>
  <div
    :style="{
      backgroundColor: statusBgColor,
    }"
    class="banner"
  >
    Your Status:
    <span style="color: #fff">{{ statusText }}</span>
  </div>
  <div class="left_panel_block" style="padding: 10px 0px 0px 0px">
    <div style="display: flex; justify-content: space-between">
      <!-- ======== TODOC2: Your Status is ========== -->
      <div class="deviceName">
        {{ this.$store.state.account.session.DeviceName }}
      </div>

      <div class="buttons">
        <div class="buttonWithPopup" style="margin-right: 17px">
          <!-- <transition name="fade">
            <div v-if="isCanPause || isCanResume">
              <button
                v-if="isCanPause"
                class="settingsBtn"
                style="background: var(--background-color); position: relative"
                v-on:click="onPauseMenu"
                v-click-outside="onPauseMenuClickOutside"
              >
                <imgPause />
              </button>

              <button
                v-else-if="isCanResume"
                class="settingsBtnResume"
                style="position: relative"
                v-on:click="onPauseResume(null)"
              >
                <img src="@/assets/resume.svg" style="margin-left: 2px" />
              </button>
            </div>
          </transition> -->

          <!-- Popup -->
          <div
            class="popup"
            v-bind:class="{
              popupMin: isMinimizedUI,
            }"
          >
            <div
              class="popuptext"
              v-bind:class="{
                show: isCanShowPauseMenu,
                popuptextMin: isMinimizedUI,
              }"
            >
              <div
                class="popup_menu_block_clickable"
                v-on:click="onPauseMenuItem(5 * 60)"
              >
                <button>Pause for 5 min</button>
              </div>
              <div class="popup_dividing_line" />
              <div
                class="popup_menu_block_clickable"
                v-on:click="onPauseMenuItem(30 * 60)"
              >
                <button>Pause for 30 min</button>
              </div>
              <div class="popup_dividing_line" />
              <div
                class="popup_menu_block_clickable"
                v-on:click="onPauseMenuItem(1 * 60 * 60)"
              >
                <button>Pause for 1 hour</button>
              </div>
              <div class="popup_dividing_line" />
              <div
                class="popup_menu_block_clickable"
                v-on:click="onPauseMenuItem(3 * 60 * 60)"
              >
                <button>Pause for 3 hours</button>
              </div>
            </div>
          </div>
        </div>

        <div style="min-width: 50px; margin-left: auto; margin-right: 0">
          <SwitchProgress
            v-bind:class="{ lowOpacity: isCanResume }"
            :onChecked="onChecked"
            :isChecked="isChecked"
            :isProgress="isProgress"
          />
        </div>
      </div>
    </div>

    <!-- SECOND LINE start-->
    <div style="display: flex; justify-content: space-between">
      <!-- PAUSE BUTTON start-->
      <div
        v-if="isCanResume"
        class="buttonWithPopup"
        style="align-items: start"
      >
        <button
          class="noBordersBtn"
          style="padding: 0"
          v-on:click="onAddPauseTimeMenu"
          v-click-outside="onPauseMenuClickOutside"
        >
          <div class="small_text" align="left" style="min-width: 80px">
            {{ pauseTimeLeftText }}
          </div>
        </button>

        <!-- Popup -->
        <div
          style="background: red; margin-top: -5px"
          class="popup"
          v-bind:class="{
            popupMinShiftedRight: true,
          }"
        >
          <div
            class="popuptext"
            v-bind:class="{
              show: isPauseExtendMenuShow,
              popuptextMinShiftedRight: true,
            }"
          >
            <div
              class="popup_menu_block_clickable"
              v-on:click="onPauseMenuItem(null)"
            >
              <button>Resume now</button>
            </div>
            <div class="popup_dividing_line" />
            <div
              class="popup_menu_block_clickable"
              v-on:click="onPauseMenuItem(5 * 60)"
            >
              <button>Resume in 5 min</button>
            </div>
            <div class="popup_dividing_line" />
            <div
              class="popup_menu_block_clickable"
              v-on:click="onPauseMenuItem(30 * 60)"
            >
              <button>Resume in 30 min</button>
            </div>
            <div class="popup_dividing_line" />
            <div
              class="popup_menu_block_clickable"
              v-on:click="onPauseMenuItem(1 * 60 * 60)"
            >
              <button>Resume in 1 hour</button>
            </div>
            <div class="popup_dividing_line" />
            <div
              class="popup_menu_block_clickable"
              v-on:click="onPauseMenuItem(3 * 60 * 60)"
            >
              <button>Resume in 3 hours</button>
            </div>
          </div>
        </div>
      </div>
      <!-- PAUSE BUTTON end-->

      <!-- Vlad: don't show inverse split tunnel mode -->
      <!--
      <transition name="fade">
        <button
          v-show="this.$store.getters['vpnState/isInverseSplitTunnel']"
          class="noBordersTextBtn"
          v-on:click="onSplitTunnelInfoClick"
        >
          <div class="small_text_warning">
            Inverse Split Tunnel mode is active
          </div>
        </button>
      </transition>
      -->

      <transition name="fade">
        <div v-if="AppWhitelistAndConnected" class="small_text_warning">
          App Whitelist is active
        </div>
      </transition>
    </div>
    <!-- SECIND LINE end-->
  </div>
</template>

<script>
const sender = window.ipcSender;

import SwitchProgress from "@/components/controls/control-switch.vue";
import imgPause from "@/components/images/img-pause.vue";
import { GetTimeLeftText } from "@/helpers/renderer";
import vClickOutside from "click-outside-vue3";

export default {
  directives: {
    clickOutside: vClickOutside.directive,
  },
  components: {
    SwitchProgress,
    imgPause,
  },
  props: ["onChecked", "onPauseResume", "isChecked", "isProgress"],
  data: () => ({
    isPauseMenuAllowed: false,
    isPauseExtendMenuShow: false,
    pauseTimeUpdateTimer: null,
    pauseTimeLeftText: "",
  }),
  mounted() {
    this.startPauseTimer();
  },
  computed: {
    isMinimizedUI: function () {
      return this.$store.state.settings.minimizedUI;
    },
    protectedText: function () {
      if (this.$store.getters["vpnState/isPaused"]) return "Paused";
      if (this.isChecked !== true || this.isCanResume) return "Disconnected";
      return "Connected";
    },
    statusColor() {
      return this.protectedText === "Connected"
        ? "#4eaf51"
        : this.protectedText === "Paused"
          ? "yellow"
          : "#ff6258";
    },
    isConnected: function () {
      return this.$store.getters["vpnState/isConnected"];
    },
    pauseConnectionTill: function () {
      return this.$store.state.vpnState?.connectionInfo?.PausedTill;
    },
    isPaused: function () {
      return this.$store.getters["vpnState/isPaused"];
    },
    isCanPause: function () {
      if (!this.isConnected) return false;
      if (this.isProgress === true) return false;
      if (this.$store.state.uiState.isPauseResumeInProgress === true)
        return false;

      var connInfo = this.$store.state.vpnState.connectionInfo;
      if (connInfo === null) return false;
      if (!this.isPaused) return true;
      return false;
    },
    isCanResume: function () {
      if (this.isCanPause) return false;
      if (!this.isConnected) return false;
      if (this.isProgress === true) return false;
      if (this.$store.state.uiState.isPauseResumeInProgress === true)
        return false;

      if (this.isPaused) return true;
      return false;
    },
    isCanShowPauseMenu: function () {
      return this.isCanPause && this.isPauseMenuAllowed;
    },
    AppWhitelistAndConnected: function () {
      return (
        this.$store.state.vpnState.splitTunnelling?.IsAppWhitelistEnabled &&
        this.isConnected
      );
    },
    statusText() {
      if (this.protectedText === "Disconnected") {
        return " Disconnected";
      }
      if (this.$store.state.vpnState.splitTunnelling?.IsEnabled) {
        return " Partially Protected";
      }
      return " Fully Protected";
    },
    statusBgColor() {
      if (this.protectedText === "Disconnected") {
        return "#ff6258";
      }
      return this.$store.state.vpnState.splitTunnelling?.IsEnabled
        ? "#4eaf51"
        : "#0766ff";
    },
  },
  watch: {
    isPaused() {
      this.startPauseTimer();
    },
  },
  methods: {
    onSplitTunnelInfoClick() {
      sender.ShowSplitTunnelSettings();
    },
    onPauseMenuClickOutside() {
      this.isPauseExtendMenuShow = false;
      this.isPauseMenuAllowed = false;
    },
    onPauseMenu() {
      if (this.isPauseMenuAllowed != true) this.onPauseResume(null);
      this.isPauseMenuAllowed = !this.isPauseMenuAllowed;
    },
    onAddPauseTimeMenu() {
      if (this.isCanResume != true) this.isPauseExtendMenuShow = false;
      else this.isPauseExtendMenuShow = !this.isPauseExtendMenuShow;
    },
    onPauseMenuItem(seconds) {
      this.isPauseMenuAllowed = false;
      this.isPauseExtendMenuShow = false;
      if (this.onPauseResume != null) this.onPauseResume(seconds);
    },
    startPauseTimer() {
      if (this.pauseTimeUpdateTimer) return;
      if (!this.pauseConnectionTill) return;

      this.pauseTimeUpdateTimer = setInterval(() => {
        this.pauseTimeLeftText = GetTimeLeftText(this.pauseConnectionTill);

        if (!this.isPaused) {
          clearInterval(this.pauseTimeUpdateTimer);
          this.pauseTimeUpdateTimer = null;
        }
      }, 1000);

      this.pauseTimeLeftText = GetTimeLeftText(this.pauseConnectionTill);
    },
  },
};
</script>

<!-- Add "scoped" attribute to limit CSS to this component only -->
<style scoped lang="scss">
@use "@/components/scss/constants";
@use "@/components/scss/popup";
$shadow:
  0px 3px 1px rgba(0, 0, 0, 0.06),
  0px 3px 8px rgba(0, 0, 0, var(--shadow-opacity-koef));

.main {
  @extend .left_panel_block;
  margin-top: 26px;
}

div.banner {
  text-align: center;
  font-size: 14px;
  font-weight: 500;
  color: #fff;
  padding: 3px;
}

div.deviceName {
  // font-size: 16px;
  font-weight: 500;
  color: var(--text-color);
}

.buttons {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.lowOpacity {
  opacity: 0.5;
}

.large_text {
  font-style: normal;
  font-weight: 600;
  letter-spacing: -0.3px;
  font-size: 24px;
  line-height: 29px;
}

.small_text {
  font-size: 14px;
  line-height: 17px;
  letter-spacing: -0.3px;
  color: var(--text-color-details);
}

.small_text_warning {
  font-size: 12px;
  font-weight: 600;
  letter-spacing: -0.3px;
  color: var(--warning-color);
}

.settingsBtn {
  float: right;

  width: 32px;
  height: 32px;

  padding: 0px;
  border: none;
  border-radius: 50%;
  background-color: #ffffff;
  outline-width: 0;
  cursor: pointer;

  box-shadow: $shadow;

  // centering content
  display: flex;
  justify-content: center;
  align-items: center;
}

.settingsBtn:hover {
  background-color: #f0f0f0;
}

.settingsBtnResume {
  @extend .settingsBtn;
  background-color: #449cf8;
}

.settingsBtnResume:hover {
  background-color: #3377ff;
}

.popup_menu_block_clickable {
  @extend .popup_menu_block;
  cursor: pointer;
}
//------------------------------------------------------
// in use for minimalistic UI
// (reduced width and position shifted left)
.popupMin .popuptextMin {
  min-width: 160px;
  max-width: 160px;
  margin-left: -80px;
}
//------------------------------------------------------
// (reduced width and position shifted right)
.popupMinShiftedRight .popuptextMinShiftedRight {
  min-width: 160px;
  max-width: 160px;
  margin-left: 8px;
}
// arrow location shifted left
.popupMinShiftedRight .popuptextMinShiftedRight::after {
  margin-left: -55px;
}
</style>
