<template>
  <div calss="main" v-on:click="onMouseClick">
    <div class="popup_description_text">
      <div v-if="isTheCurrentLocation">Your current location</div>
    </div>
    <div class="popup_description_text">
      <div v-if="isExitServerCountrySameAsEntry">
        When using multihop you must select entry and exit servers in different
        countries. Please select a different entry or exit server.
      </div>
    </div>
    <div class="flexRow">
      <serverNameControl
        :server="location"
        isFullName="true"
        style="max-width: 90%"
      />
      <serverPingInfoControl :server="location" style="margin-left: 9px" />
    </div>

    <div style="height: 12px" />
    <button class="master" v-if="isCanConnect" v-on:click="onConnect(location)">
      Connect to server
    </button>
    <button class="master" v-if="isCanDisconnect" v-on:click="onDisconnect">
      Disconnect
    </button>

    <div v-if="isPaused">
      <div style="height: 20px" v-if="isCanConnect || isCanDisconnect" />
      <div v-if="pauseTimeLeftText" class="popup_description_text">
        Connection will resume automatically in
      </div>
      <div class="popup_pause_text">
        {{ pauseTimeLeftText }}
      </div>

      <!--
      <div style="height: 12px" />
      <button class="master" v-on:click="onResume()">
        <div class="btnResumeText">
          RESUME
        </div>
      </button>
      -->
    </div>
  </div>
</template>

<script>
import serverNameControl from "@/components/controls/control-server-name.vue";
import serverPingInfoControl from "@/components/controls/control-server-ping.vue";
import { VpnStateEnum } from "@/store/types";
import { GetTimeLeftText } from "@/helpers/renderer";

export default {
  props: ["location", "onConnect", "onDisconnect", "onMouseClick", "onResume"],
  components: {
    serverNameControl,
    serverPingInfoControl,
  },
  data: () => ({
    pauseTimeUpdateTimer: null,
    pauseTimeLeftText: "",
  }),
  mounted() {
    this.startPauseTimer();
  },
  computed: {
    // needed for watcher
    pauseConnectionTill: function () {
      return this.$store.state.vpnState?.connectionInfo?.PausedTill;
    },
    isPaused: function () {
      return this.$store.getters["vpnState/isPaused"];
    },
    isTheCurrentLocation: function () {
      return (
        this.location === this.$store.state.location ||
        this.location === this.$store.state.locationIPv6
      );
    },

    isExitServerCountrySameAsEntry: function () {
      if (this.location == null || this.location.gateway == null) return false;
      return (
        this.$store.state.settings.isMultiHop &&
        this.location.country_code ===
          this.$store.state.settings.serverEntry.country_code
      );
    },

    isCanDisconnect() {
      if (this.$store.state.vpnState.connectionState !== VpnStateEnum.CONNECTED)
        return false;
      if (this.location == null || this.location.gateway == null) return false;

      if (
        (this.$store.state.settings.isMultiHop &&
          this.location.country_code ===
            this.$store.state.settings.serverExit.country_code) ||
        (this.$store.state.settings.isMultiHop == false &&
          this.location.country_code ===
            this.$store.state.settings.serverEntry.country_code)
      )
        return true;

      return false;
    },

    isCanConnect: function () {
      // selected curent users location (not a server)
      if (this.isTheCurrentLocation) return false;
      // not allowed multi-hop connect for servers in same country
      if (this.isExitServerCountrySameAsEntry) return false;
      if (this.isCanDisconnect) return false;
      if (this.location != null && this.location.gateway == null) return false;
      return true;
    },

    isAllowedExitServer: function () {
      if (this.$store.state.settings.isMultiHop === false) return true;
      if (this.location == null) return true;

      if (
        location.country_code ===
        this.$store.state.settings.serverExit.country_code
      )
        return false;
      return true;
    },
  },
  watch: {
    isPaused() {
      this.startPauseTimer();
    },
  },
  methods: {
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
.popup_description_text {
  text-align: left;
  font-size: 12px;
  line-height: 14px;
  letter-spacing: -0.3px;
  opacity: 0.5;
  margin-bottom: 10px;
}

.popup_pause_text {
  font-size: 16px;
  line-height: 19px;
  text-align: left;
  margin-top: -5px;
}

.btnResumeText {
  font-size: 17px;
  line-height: 15px;
  text-align: center;
  letter-spacing: -0.0857143px;
  text-transform: uppercase;
  color: #ffffff;
  mix-blend-mode: normal;
  opacity: 0.8;
}
</style>
