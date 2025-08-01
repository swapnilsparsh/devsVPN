<template>
  <div id="main" class="row">
    <div id="leftPanel">
      <div style="margin: 20px">
        <div class="large_text">Device limit reached</div>
        <div style="height: 22px"></div>
        <div class="small_text">
          According to your subscription plan you can use your privateLINE account only
          on {{ devicesMaxLimit }} devices.
        </div>

        <div style="height: 24px"></div>

        <button class="master" v-if="isCanUpgrade" v-on:click="onUpgrade">
          Upgrade your subscription
        </button>

        <div style="height: 16px"></div>

        <button
          v-bind:class="{
            master: isCanUpgrade !== true,
            slave: isCanUpgrade === true,
          }"
          v-if="isCanForceLogout"
          v-on:click="onForceLogout"
        >
          Log out from all devices
        </button>

        <div style="height: 16px"></div>
        <div v-if="isLegacyAccount == false && this.DeviceManagementURL">
          <button class="slave" v-on:click="onVisitDeviceManagement">
            {{ devManagementButtonText }}
          </button>
        </div>

        <div style="height: 16px"></div>
        <div class="centered">
          <button class="link linkFont" v-on:click="onTryAgain">Go back</button>
        </div>
      </div>

      <div class="elementFooter">
        <div class="small_text2">Do you think there is some issue?</div>
        <div style="height: 2px"></div>
        <button class="link linkFont" v-on:click="onContactSupport">
          Contact Support Team
        </button>
      </div>
    </div>

    <div id="rightPanel">
      <div>
        <img src="@/assets/devices-big.svg" />
      </div>
    </div>
  </div>
</template>

<script>
import { isValidURL } from "@/helpers/helpers";
const sender = window.ipcSender;

export default {
  mounted() {
    let params = history.state.params;
    if (params) {
      this.accountID = params.accountID;
      this.devicesMaxLimit = params.devicesMaxLimit;
      this.CurrentPlan = params.CurrentPlan;
      this.PaymentMethod = params.PaymentMethod;
      this.Upgradable = params.Upgradable;
      this.UpgradeToPlan = params.UpgradeToPlan;
      this.UpgradeToURL = params.UpgradeToURL;
      this.DeviceManagement = params.DeviceManagement;
      this.DeviceManagementURL = params.DeviceManagementURL;
    } else {
      console.error("AccountLimit view: history params are not defined!");
    }

    this.extraArgs = params.extraArgs; //{ confirmation2FA }
  },
  data: function () {
    return {
      accountID: null,
      devicesMaxLimit: 0,
      CurrentPlan: null,
      PaymentMethod: null,
      Upgradable: null,
      UpgradeToPlan: null,
      UpgradeToURL: null,
      DeviceManagement: false,
      DeviceManagementURL: "",
      extraArgs: null,
    };
  },
  computed: {
    isCanUpgrade: function () {
      return this.Upgradable;
    },
    isCanForceLogout: function () {
      if (this.accountID == null || this.accountID === "") return false;
      return true;
    },
    isLegacyAccount: function () {
      return typeof this.accountID === "string" &&
        this.accountID.startsWith("ivpn") &&
        this.accountID.length <= 12
        ? true
        : false;
    },
    devManagementButtonText: function () {
      return this.DeviceManagement
        ? "Visit Device Management"
        : "Enable Device Management";
    },
  },
  methods: {
    onTryAgain: function () {
      this.$router.push("/");
    },
    onForceLogout: async function () {
      this.$router.push({
        name: "Main",
        state: {
          params: {
            forceLoginAccount: this.accountID,
            extraArgs: JSON.parse(JSON.stringify(this.extraArgs)),
          },
        },
      });
    },
    onUpgrade: function () {
      if (isValidURL(this.UpgradeToURL))
        sender.shellOpenExternal(this.UpgradeToURL);
      else sender.shellOpenExternal(`https://account.privateline.io`);
    },
    onContactSupport: function () {
      sender.shellOpenExternal(`https://privateline.io/support`);
    },
    onVisitDeviceManagement: function () {
      sender.shellOpenExternal(this.DeviceManagementURL);
    },
  },
};
</script>

<style scoped lang="scss">
@use "@/components/scss/constants";

#main {
  height: 100%;
  display: flex;
  flex-direction: row;
}

#leftPanel {
  min-width: 320px;
  max-width: 320px;

  flex-direction: column;
  display: flex;
  justify-content: center;
  align-items: center;
}
#rightPanel {
  flex-direction: row;
  display: flex;
  align-items: center;
  justify-content: center;

  width: 100%;
  background: #f8c373;
}

.large_text {
  font-weight: 600;
  font-size: 18px;
  line-height: 120%;

  text-align: center;
}

.small_text {
  font-size: 15px;
  line-height: 18px;
  text-align: center;
  letter-spacing: -0.3px;

  color: var(--text-color-details);
}

.small_text2 {
  font-size: 14px;
  line-height: 17px;
  text-align: center;
  letter-spacing: -0.3px;

  color: var(--text-color-details);
}

.verticalSpace {
  margin-top: auto;
  margin-right: 0;
}
.linkFont {
  font-size: 12px;
  line-height: 18px;
  text-align: center;
  letter-spacing: -0.4px;
}

.centered {
  flex-direction: column;
  display: flex;
  justify-content: center;
  align-items: center;
}

.elementFooter {
  @extend .centered;
  position: fixed;
  bottom: 0%;
  margin-bottom: 36px;
}
</style>
