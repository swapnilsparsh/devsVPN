<template>
  <div class="flexColumn">
    <!-- HEADER -->
    <div class="flexRow serversButtonsHeader">
      <div>
        <button v-on:click="goBack" class="stateButtonOff">
          <imgArrowLeft class="serversButtonsBack" />
        </button>
      </div>

      <!-- <div class="serversButtonsSpace" /> -->

      <div style="width: 100%" v-if="isFastestServerConfig === false">
        <div class="flexRow" style="flex-grow: 1">
          <div style="flex-grow: 1">
            <button
              style="width: 100%; font-weight: 600"
              v-on:click="showAll"
              class="stateButtonOff stateButtonLeft"
              v-bind:class="{ stateButtonOn: !isFavoritesView }"
            >
              all servers
            </button>
          </div>

          <div style="flex-grow: 1">
            <button
              style="width: 100%; font-weight: 600"
              v-on:click="showFavorites"
              class="stateButtonOff stateButtonRight"
              v-bind:class="{ stateButtonOn: isFavoritesView }"
            >
              favorites
            </button>
          </div>
        </div>
      </div>

      <div style="width: 100%" v-if="isFastestServerConfig">
        <div class="flexRow" style="flex-grow: 1">
          <div style="flex-grow: 1">
            <button
              style="width: 100%"
              v-on:click="showAll"
              class="stateButtonOff"
              v-bind:class="{ stateButtonOn: !isFavoritesView }"
            >
              fastest server settings
            </button>
          </div>
        </div>
      </div>
    </div>

    <!-- EMPTY FAVORITE SERVERS DESCRIPTION BLOCK -->
    <div v-if="isShowFavoriteDescriptionBlock">
      <div class="text">
        Your favorite (<img :src="favoriteImageActive()" />) servers will be
        displayed here
      </div>
    </div>

    <!-- FILTER -->
    <div class="commonMargins flexRow" v-if="!isShowFavoriteDescriptionBlock">
      <input
        id="filter"
        class="styled"
        placeholder="Search for a server"
        v-model="filter"
      />

      <div class="buttonWithPopup">
        <button
          class="noBordersBtn sortBtn sortBtnPlatform"
          v-on:click="onSortMenuClicked()"
          v-click-outside="onSortMenuClickedOutside"
        >
          <img :src="sortImage" />
        </button>

        <!-- Popup -->
        <div
          class="popup popupMinShifted"
          v-bind:class="{
            popupMinShifted: isMinimizedUI,
          }"
        >
          <div
            ref="pausePopup"
            class="popuptext"
            v-bind:class="{
              show: isSortMenu,
              popuptextMinShifted: isMinimizedUI,
            }"
          >
            <div class="popup_menu_block">
              <div class="sortSelectedImg">
                <img :src="selectedImage" v-if="sortTypeStr === 'City'" />
              </div>
              <button class="flexRowRestSpace" v-on:click="onSortType('City')">
                City
              </button>
            </div>

            <div class="popup_dividing_line" />
            <div class="popup_menu_block">
              <div class="sortSelectedImg">
                <img :src="selectedImage" v-if="sortTypeStr === 'Country'" />
              </div>
              <button
                class="flexRowRestSpace"
                v-on:click="onSortType('Country')"
              >
                Country
              </button>
            </div>

            <div class="popup_dividing_line" />
            <div class="popup_menu_block">
              <div class="sortSelectedImg">
                <img :src="selectedImage" v-if="sortTypeStr === 'Latency'" />
              </div>
              <button
                class="flexRowRestSpace"
                v-on:click="onSortType('Latency')"
              >
                Latency
              </button>
            </div>

            <div class="popup_dividing_line" />
            <div class="popup_menu_block">
              <div class="sortSelectedImg">
                <img :src="selectedImage" v-if="sortTypeStr === 'Proximity'" />
              </div>
              <button
                class="flexRowRestSpace"
                v-on:click="onSortType('Proximity')"
              >
                Proximity
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>

    <div
      v-if="isFastestServerConfig"
      class="small_text"
      style="margin-bottom: 5px"
    >
      Disable servers you do not want to be choosen as the fastest server
    </div>

    <!-- SERVERS LIST BLOCK -->
    <div
      ref="scrollArea"
      @scroll="recalcScrollButtonVisiblity()"
      class="commonMargins flexColumn scrollableColumnContainer"
    >
      <!-- FASTEST & RANDOM SERVER -->
      <div v-if="isFavoritesView == false && isFastestServerConfig === false">
        <!-- <div class="flexRow" v-if="!isMultihop">
          <button
            class="serverSelectBtn flexRow"
            v-on:click="onFastestServerClicked()"
          >
            <serverNameControl class="serverName" :isFastestServer="true" />
          </button>
          <button class="noBordersBtn" v-on:click="onFastestServerConfig()">
            <img :src="settingsImage" />
          </button>
        </div> -->
        <!-- RANDOM -->
        <!-- <button
          class="serverSelectBtn flexRow"
          v-on:click="onRandomServerClicked()"
        >
          <serverNameControl class="serverName" :isRandomServer="true" />
        </button> -->
      </div>

      <!-- SERVERS LIST -->
      <div
        class="flexRow"
        v-for="server of filteredServers"
        v-bind:key="server.gateway"
      >
        <button
          class="serverSelectBtn"
          v-on:click="onServerSelected(server)"
          v-bind:class="{
            disabledButton: isInaccessibleServer(server) !== null,
          }"
        >
          <div class="flexRow" style="position: relative; overflow: hidden">
            <serverNameControl
              class="serverName"
              :SecondLineMaxWidth="
                isFastestServerConfig === true ? '202px' : null
              "
              :server="server"
              :isFavoriteServersView="isFavoritesView"
              :isCountryFirst="sortTypeStr === 'Country'"
              :onExpandClick="onServerExpandClick"
              :isExpanded="isServerHostsExpanded(server)"
            />

            <div
              class="flexColumn"
              v-if="isFastestServerConfig !== true"
              style="margin-top: -22px"
            >
              <div class="flexRow">
                <serverPingInfoControl
                  class="pingInfo"
                  :server="server"
                  :isShowPingTime="true"
                />

                <img
                  :src="favoriteImage(server)"
                  v-on:click="favoriteClicked($event, server)"
                />
              </div>
            </div>
          </div>

          <!--HOSTS (expanded list)-->
          <div
            v-if="
              isServerHostsExpanded(server) === true &&
              isFastestServerConfig !== true
            "
          >
            <div
              class="flexRow"
              v-for="host of server.hosts"
              v-bind:key="host.hostname"
            >
              <button
                class="serverHostSelectBtn"
                v-on:click.stop
                v-on:click="onServerHostSelected(server, host)"
              >
                <div style="display: flex; margin-top: 2px; margin-bottom: 6px">
                  <div
                    title="Host name"
                    style="
                      text-align: left;
                      margin-left: 40px;
                      min-width: 154px;
                    "
                  >
                    {{ host.hostname }}
                  </div>

                  <!-- host load + favorite-->
                  <div>
                    <div class="flexRow">
                      <div class="pingInfo" style="text-align: right">
                        <div
                          title="Server load"
                          style="
                            margin-right: 10px;
                            color: var(--text-color-details);
                          "
                        >
                          {{ Math.round(host.load) }}%
                        </div>
                      </div>

                      <img
                        v-if="server.hosts.length > 1"
                        :src="favoriteImage(server, host)"
                        v-on:click="favoriteClicked($event, server, host)"
                      />
                    </div>
                  </div>
                </div>
              </button>
            </div>
          </div>
        </button>

        <div class="flexRow" v-if="isFastestServerConfig">
          <!-- CONFIG -->
          <SwitchProgress
            :onChecked="
              (value, event) => {
                configFastestSvrClicked(server, event);
              }
            "
            :isChecked="!isSvrExcludedFomFastest(server)"
          />
        </div>
      </div>

      <!-- SCROLL DOWN BUTTON -->
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
  </div>
</template>

<script>
const sender = window.ipcSender;
import serverNameControl from "@/components/controls/control-server-name.vue";
import serverPingInfoControl from "@/components/controls/control-server-ping.vue";
import SwitchProgress from "@/components/controls/control-switch-small.vue";
import imgArrowLeft from "@/components/images/arrow-left.vue";
import { Platform, PlatformEnum } from "@/platform/platform";
import { enumValueName, getDistanceFromLatLonInKm } from "@/helpers/helpers";
import {
  CheckIsInaccessibleServer,
  CheckAndNotifyInaccessibleServer,
} from "@/helpers/helpers_servers";
import { ServersSortTypeEnum } from "@/store/types";

import Image_arrow_left_windows from "@/assets/arrow-left-windows.svg";
import Image_arrow_left_macos from "@/assets/arrow-left-macos.svg";
import Image_arrow_left_linux from "@/assets/arrow-left-linux.svg";
import Image_search_windows from "@/assets/search-windows.svg";
import Image_search_macos from "@/assets/search-macos.svg";
import Image_search_linux from "@/assets/search-linux.svg";
import Image_settings_windows from "@/assets/settings-windows.svg";
import Image_settings_macos from "@/assets/settings-macos.svg";
import Image_settings_linux from "@/assets/settings-linux.svg";
import Image_sort from "@/assets/sort.svg";
import Image_check_thin from "@/assets/check-thin.svg";
import Image_star_active from "@/assets/star-active.svg";
import Image_star_inactive from "@/assets/star-inactive.svg";

import vClickOutside from "click-outside-vue3";

export default {
  directives: {
    clickOutside: vClickOutside.directive,
  },
  props: [
    "onBack",
    "onServerChanged",
    "isExitServer",
    "onFastestServer",
    "onRandomServer",
  ],
  components: {
    serverNameControl,
    serverPingInfoControl,
    SwitchProgress,
    imgArrowLeft,
  },
  data: function () {
    return {
      filter: "",
      isFastestServerConfig: false,
      isSortMenu: false,
      isShowScrollButton: false,
      expandedGateways: [], // list of server.gateway strings (list of gateways which is expanded to show server hosts)
    };
  },
  mounted() {
    this.recalcScrollButtonVisiblity();
    const resizeObserver = new ResizeObserver(this.recalcScrollButtonVisiblity);
    resizeObserver.observe(this.$refs.scrollArea);
  },
  computed: {
    isMinimizedUI: function () {
      return this.$store.state.settings.minimizedUI;
    },
    isFavoritesView: function () {
      return this.$store.state.uiState.serversFavoriteView;
    },
    isMultihop: function () {
      return this.$store.state.settings.isMultiHop;
    },
    isShowFavoriteDescriptionBlock: function () {
      return this.isFavoritesView === true && this.favorites.length == 0;
    },
    servers: function () {
      return this.$store.getters["vpnState/activeServers"];
    },

    sortTypeStr: function () {
      return enumValueName(
        ServersSortTypeEnum,
        this.$store.state.settings.serversSortType
      );
    },

    favorites: function () {
      // Favorite servers and hosts for current protocol
      return this.$store.getters["settings/favoriteServersAndHosts"];
    },

    filteredServers: function () {
      let store = this.$store;
      let sType = store.state.settings.serversSortType;
      const funcGetPing = this.$store.getters["vpnState/funcGetPing"];
      function compare(a, b) {
        switch (sType) {
          case ServersSortTypeEnum.City:
            return a.city.localeCompare(b.city);

          case ServersSortTypeEnum.Country: {
            if (!a.country && !b.country) return 0;
            if (!a.country) return 1;

            let ret = 0;
            ret = a.country.localeCompare(b.country);
            if (ret != 0) return ret;
            // If countries are the same - compare cities
            if (a.city && b.city) return a.city.localeCompare(b.city);
            return ret;
          }

          case ServersSortTypeEnum.Latency: {
            const aPing = funcGetPing(a);
            const bPing = funcGetPing(b);
            if (aPing && bPing) return aPing - bPing;
            if (aPing && !bPing) return -1;
            if (!aPing && bPing) return 1;
            return 0;
          }

          case ServersSortTypeEnum.Proximity: {
            const l = store.getters["getLastRealLocation"];
            if (l == null) return 0;

            var distA = getDistanceFromLatLonInKm(
              l.latitude,
              l.longitude,
              a.latitude,
              a.longitude
            );
            var distB = getDistanceFromLatLonInKm(
              l.latitude,
              l.longitude,
              b.latitude,
              b.longitude
            );

            if (distA === distB) return 0;
            if (distA < distB) return -1;

            return 1;
          }
        }
      }

      function serverToSkip() {
        // For Multi-Hop:
        // -skip entry-server for exit server selection
        // -skip exit-server for entry server selection
        if (!this.isMultihop) return null;
        if (this.isExitServer) {
          if (!this.$store.state.settings.isRandomServer)
            return this.$store.state.settings.serverEntry;
        } else {
          if (!this.$store.state.settings.isRandomExitServer)
            return this.$store.state.settings.serverExit;
        }
        return null;
      }

      let servers = this.servers;
      if (this.isFavoritesView) servers = this.favorites;

      let svrToSkip = serverToSkip.bind(this)();
      //if (!svrToSkip && !this.filter) return servers.slice().sort(compare);

      let filter = this.filter.toLowerCase();
      let filtered = servers.filter((s) => {
        if (s.gateway === svrToSkip?.gateway) return false;
        if (!this.filter) return true;
        return (
          (s.favHost && s.favHost.hostname.toLowerCase().includes(filter)) || // only for favorite hosts (host object extended by all properties from parent server object +favHostParentServerObj +favHost)
          (s.city && s.city.toLowerCase().includes(filter)) ||
          (s.country && s.country.toLowerCase().includes(filter)) ||
          (s.country_code && s.country_code.toLowerCase().includes(filter))
        );
      });

      return filtered.slice().sort(compare);
    },

    arrowLeftImagePath: function () {
      switch (Platform()) {
        case PlatformEnum.Windows:
          return Image_arrow_left_windows;
        case PlatformEnum.macOS:
          return Image_arrow_left_macos;
        default:
          return Image_arrow_left_linux;
      }
    },
    searchImage: function () {
      if (this.filter) return null;

      switch (Platform()) {
        case PlatformEnum.Windows:
          return Image_search_windows;
        case PlatformEnum.macOS:
          return Image_search_macos;
        default:
          return Image_search_linux;
      }
    },
    settingsImage: function () {
      switch (Platform()) {
        case PlatformEnum.Windows:
          return Image_settings_windows;
        case PlatformEnum.macOS:
          return Image_settings_macos;
        default:
          return Image_settings_linux;
      }
    },
    sortImage: function () {
      return Image_sort;
    },
    selectedImage: function () {
      return Image_check_thin;
    },
  },

  methods: {
    goBack: function () {
      if (this.isFastestServerConfig) {
        this.filter = "";
        this.isFastestServerConfig = false;
        return;
      }
      if (this.onBack != null) this.onBack();
    },

    isServerHostsExpanded: function (server) {
      if (
        this.$store.state.settings.showHosts !== true ||
        this.isFastestServerConfig === true ||
        this.$store.state.uiState.serversFavoriteView === true
      )
        return undefined; //hide expand button
      return this.expandedGateways.includes(server.gateway);
    },
    onServerExpandClick: function (server) {
      var index = this.expandedGateways.indexOf(server.gateway);
      if (index === -1) this.expandedGateways.push(server.gateway);
      else this.expandedGateways.splice(index, 1);

      setTimeout(() => {
        this.recalcScrollButtonVisiblity();
      }, 0);
    },

    checkAndNotifyInaccessibleServer: async function (server) {
      return CheckAndNotifyInaccessibleServer(this.isExitServer, server);
    },
    // isInaccessibleServer returns:
    // - null if server is acceptble
    // - object { sameGateway: true } - servers have same gateway
    // - object { sameCountry: true } - servers are from same country (only if this.$store.state.settings.multihopWarnSelectSameCountries === true)
    // - objext { sameISP: true }     - servers are operated by same ISP (only if this.$store.state.settings.multihopWarnSelectSameISPs === true)
    isInaccessibleServer: function (server) {
      return CheckIsInaccessibleServer(this.isExitServer, server);
    },

    onServerSelected: async function (server) {
      if (server.favHost) {
        return this.onServerHostSelected(
          server.favHostParentServerObj,
          server.favHost
        );
      }
      if ((await this.checkAndNotifyInaccessibleServer(server)) == false)
        return;
      this.onServerChanged(server, this.isExitServer != null);
      this.onBack();
    },
    onServerHostSelected: async function (server, host) {
      if ((await this.checkAndNotifyInaccessibleServer(server)) == false)
        return;
      this.onServerChanged(server, this.isExitServer != null, host.hostname);
      this.onBack();
    },

    onSortMenuClickedOutside: function () {
      this.isSortMenu = false;
    },
    onSortMenuClicked: function () {
      this.isSortMenu = !this.isSortMenu;
    },
    onSortType: function (sortTypeStr) {
      this.$store.dispatch(
        "settings/serversSortType",
        ServersSortTypeEnum[sortTypeStr]
      );
      this.isSortMenu = false;
    },
    onFastestServerClicked() {
      if (this.onFastestServer != null) this.onFastestServer();
      this.onBack();
    },
    onRandomServerClicked() {
      if (this.onRandomServer != null) this.onRandomServer();
      this.onBack();
    },
    isSvrExcludedFomFastest: function (server) {
      const sGwId = getGatewayId(server.gateway);
      const found = this.$store.state.settings.serversFastestExcludeList.find(
        (excGw) => sGwId == getGatewayId(excGw)
      );
      return found != undefined;
    },
    favoriteImage: function (server, host) {
      const settings = this.$store.state.settings;
      if (server.favHost) {
        // favorite host: only for favorite hosts (host object extended by all properties from parent server object)
        if (
          settings.hostsFavoriteListDnsNames.includes(server.favHost.dns_name)
        )
          return Image_star_active;
      } else if (host) {
        // host
        if (settings.hostsFavoriteListDnsNames.includes(host.dns_name))
          return Image_star_active;
      } else {
        //server
        if (settings.serversFavoriteList.includes(getGatewayId(server.gateway)))
          return Image_star_active;
      }
      return Image_star_inactive;
    },
    favoriteImageActive: function () {
      return Image_star_active;
    },
    onFastestServerConfig() {
      this.isFastestServerConfig = true;
      this.filter = "";
    },

    favoriteClicked: function (evt, server, host) {
      evt.stopPropagation();
      if (!server && !host) return;

      if (server.favHost) {
        return this.favoriteClicked(
          evt,
          server.favHostParentServerObj,
          server.favHost
        );
      }
      const settings = this.$store.state.settings;
      const store = this.$store;

      if (!host) {
        // favorite SERVER
        let gatewayId = server.gateway.split(".")[0]; // only gateway ID in use for serversFavoriteList ("us-tx.wg.ivpn.net" => "us-tx")
        let favorites = settings.serversFavoriteList.slice();

        if (!favorites.includes(gatewayId)) {
          console.log(`Adding favorite location ${gatewayId}`);
          favorites.push(gatewayId);
        } else {
          console.log(`Removing favorite location ${gatewayId}`);
          favorites = favorites.filter((gw) => gw != gatewayId);

          // If the server has only one host AND this host is in favorites -> remove host also
          // Reason: If server and it's single host are in favorites - we showing only server to user.
          // (refer to "settings/favoriteServersAndHosts" for details)
          if (server.hosts.length == 1) {
            // remove HOST also
            let hostDns = server.hosts[0].dns_name;
            let favHostsDns = settings.hostsFavoriteListDnsNames.slice();
            if (favHostsDns.includes(hostDns)) {
              console.log(`Removing favorite host ${hostDns} (single host)`);
              favHostsDns = favHostsDns.filter((hn) => hn != hostDns);
              store.dispatch("settings/hostsFavoriteListDnsNames", favHostsDns);
            }
          }
        }
        store.dispatch("settings/serversFavoriteList", favorites);
      } else if (host.hostname) {
        // favorite HOST
        let favHostsDns = settings.hostsFavoriteListDnsNames.slice();
        let hostDns = host.dns_name;

        if (!favHostsDns.includes(hostDns)) {
          // add host
          console.log(`Adding favorite host ${hostDns}`);
          favHostsDns.push(hostDns);
        } else {
          // remove host
          console.log(`Removing favorite host ${hostDns}`);
          favHostsDns = favHostsDns.filter((hn) => hn != hostDns);
        }
        store.dispatch("settings/hostsFavoriteListDnsNames", favHostsDns);
      }
    },
    configFastestSvrClicked(server, event) {
      if (server == null || server.gateway == null) return;
      let excludeSvrs =
        this.$store.state.settings.serversFastestExcludeList.slice();

      // work only with Gateway ID (not with full gateway name). We need it to have common 'serversFastestExcludeList' for all protocols
      const sGwId = getGatewayId(server.gateway);
      excludeSvrs = excludeSvrs.map((el) => {
        return getGatewayId(el);
      });

      if (excludeSvrs.includes(sGwId))
        excludeSvrs = excludeSvrs.filter((gw) => gw != sGwId);
      else excludeSvrs.push(sGwId);

      const activeServers = this.servers.slice();
      const notExcludedActiveServers = activeServers.filter(
        (s) => !excludeSvrs.includes(getGatewayId(s.gateway))
      );

      if (notExcludedActiveServers.length < 1) {
        sender.showMessageBoxSync({
          type: "info",
          buttons: ["OK"],
          message: "Please, keep at least one server",
          detail: "Not allowed to exclude all servers.",
        });
        event.preventDefault();
        return;
      } else
        this.$store.dispatch("settings/serversFastestExcludeList", excludeSvrs);
    },

    showFavorites: function () {
      this.$store.dispatch("uiState/serversFavoriteView", true);
      this.filter = "";

      setTimeout(() => {
        this.recalcScrollButtonVisiblity();
      }, 500);
    },
    showAll: function () {
      this.$store.dispatch("uiState/serversFavoriteView", false);
      this.filter = "";

      setTimeout(() => {
        this.recalcScrollButtonVisiblity();
      }, 500);
    },
    recalcScrollButtonVisiblity() {
      let sa = this.$refs.scrollArea;
      if (sa == null) {
        this.isShowScrollButton = false;
        return;
      }

      const show = sa.scrollHeight > sa.clientHeight + sa.scrollTop;

      // hide - immediately; show - with 1sec delay
      if (!show) this.isShowScrollButton = false;
      else {
        setTimeout(() => {
          this.isShowScrollButton =
            sa.scrollHeight > sa.clientHeight + sa.scrollTop;
        }, 1000);
      }
    },
    onScrollDown() {
      let sa = this.$refs.scrollArea;
      if (sa == null) return;
      sa.scrollTo({
        top: sa.clientHeight * 0.9 + sa.scrollTop, //sa.scrollHeight,
        behavior: "smooth",
      });
    },
  },
};

function getGatewayId(gatewayName) {
  return gatewayName.split(".")[0];
}
</script>

<!-- Add "scoped" attribute to limit CSS to this component only -->
<style scoped lang="scss">
@use "@/components/scss/constants";
@use "@/components/scss/popup";

$paddingLeftRight: 20px;

.commonMargins {
  margin-left: $paddingLeftRight;
  margin-right: $paddingLeftRight;
}

input#filter {
  background-position: 97% 50%; //right
  background-repeat: no-repeat;
  margin-top: $paddingLeftRight;
  margin-bottom: $paddingLeftRight;
}

.disabledButton {
  opacity: 0.5;
}

.serverSelectBtn {
  border: none;
  background-color: inherit;
  outline-width: 0;
  cursor: pointer;

  min-height: 48px;
  width: 100%;

  padding: 0px;

  padding-bottom: 3px;
  padding-top: 3px;
}

.serverHostSelectBtn {
  border: none;
  background-color: inherit;
  outline-width: 0;
  cursor: pointer;

  width: 100%;

  padding: 0px;
  font-size: 14px;
  line-height: 13px;
  color: var(--text-color-details);
}

.serverHostSelectBtn:hover {
  opacity: 0.7;
}

.serverName {
  width: 100%;
  font-weight: 600;
}

.pingInfo {
  max-width: 72px;
  width: 72px;
}

.pingtext {
  margin-left: 8px;
}

.text {
  margin: $paddingLeftRight;
  margin-top: 60px;
  text-align: center;
}

.small_text {
  margin-left: $paddingLeftRight;
  margin-right: $paddingLeftRight;
  font-size: 11px;
  line-height: 13px;
  color: var(--text-color-details);
}

button.sortBtn {
  margin-left: 5px;
}

div.sortSelectedImg {
  margin-left: 11px;
  position: absolute;
  left: 0px;
  min-width: 13px;
}

//------------------------------------------------------
// in use for minimalistic UI
// (reduced width and position shifted left)
.popupMinShifted .popuptextMinShifted {
  min-width: 160px;
  max-width: 160px;
  margin-left: -125px;
}
// in use for minimalistic UI (arrow location shifted right)
.popupMinShifted .popuptextMinShifted::after {
  margin-left: 32px;
}
//------------------------------------------------------
</style>
