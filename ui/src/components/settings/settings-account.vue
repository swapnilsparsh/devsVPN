<template>
  <div class="flexColumn" style="justify-content: space-between; width: 100%">
    <div class="flexColumn" style="gap: 2rem">
      <div>
        <div class="settingsTitle">ACCOUNT DETAILS</div>
        <div class="flexRowSpace" style="align-items: flex-start">
          <div v-if="isProcessing" class="flexColumn" style="gap: 10px">
            <ShimmerEffect
              :width="'100px'"
              :height="'100px'"
              :border-radius="'100%'"
            />
            <ShimmerEffect
              v-for="(item, index) in accountShimmerItems"
              :key="index"
              :width="'350px'"
              :height="'20px'"
            />
          </div>
          <div
            v-else-if="$store.state.account.userDetails.name"
            class="flexColumn"
          >
            <img
              v-if="!profileImage"
              src="@/assets/avtar.svg"
              style="height: 100px; width: 100px"
            />
            <img
              v-else
              :src="profileImage"
              style="
                height: 100px;
                width: 100px;
                border-radius: 100%;
                border: 5px solid #fff;
                margin-bottom: 10px;
              "
            />

            <div>
              <div class="flexRow paramBlockDetailedConfig">
                <div class="defColor paramName">Name:</div>
                <div class="detailedParamValue">
                  {{ $store.state.account.userDetails.name }}
                </div>
              </div>
              <div class="flexRow paramBlockDetailedConfig">
                <div class="defColor paramName">Email:</div>
                <div class="detailedParamValue">
                  {{ $store.state.account.userDetails.email }}
                </div>
              </div>
              <div class="flexRow paramBlockDetailedConfig">
                <div class="defColor paramName">Phone:</div>
                <div class="detailedParamValue">
                  {{ $store.state.account.userDetails.phone }}
                </div>
              </div>

              <div class="flexRow paramBlockDetailedConfig">
                <div class="defColor paramName">Account Created on:</div>
                <div class="detailedParamValue">
                  {{ formattedCreatedAt }}
                </div>
              </div>

              <div class="flexRow paramBlockDetailedConfig">
                <div class="defColor paramName">Account verification:</div>
                <div class="detailedParamValue">
                  {{
                    $store.state.account.userDetails.isVerified
                      ? "Done"
                      : "Needed"
                  }}
                </div>
              </div>
            </div>
          </div>
          <div v-else>Api Error: Data couldn't be fetched at this moment.</div>
        </div>
      </div>

      <div>
        <div class="settingsTitle">SUBSCRIPTION DETAILS</div>
        <div
          v-if="$store.state.account.subscriptionData != null"
          class="flexRowSpace"
          style="align-items: flex-start"
        >
          <div
            v-if="isSubscriptionProcessing"
            class="flexColumn"
            style="gap: 10px"
          >
            <ShimmerEffect :width="'350px'" :height="'20px'" />
            <ShimmerEffect :width="'350px'" :height="'20px'" />
            <ShimmerEffect :width="'350px'" :height="'20px'" />
          </div>
          <div
            v-else-if="$store.state.account.subscriptionData.Plan"
            class="flexColumn"
            style="width: 100%"
          >
            <div class="flexRow paramBlockDetailedConfig">
              <div class="defColor paramName">Plan Name:</div>
              <div class="flexRow" style="gap: 16px">
                <div class="detailedParamValue">
                  {{ $store.state.account.subscriptionData.Plan.name }}
                </div>
                <div
                  v-if="
                    $store.state.account.subscriptionData.Plan.name === 'Free'
                  "
                  class="medium_text link"
                  @click="UpgradeSubscription"
                >
                  Upgrade
                </div>
              </div>
            </div>

            <div
              v-if="$store.state.account.subscriptionData.Plan.name === 'Group'"
              class="flexRow paramBlockDetailedConfig"
            >
              <div class="defColor paramName">Group Size:</div>

              <div class="detailedParamValue">
                {{ $store.state.account.subscriptionData.group_size }}
              </div>
            </div>

            <div class="flexRow paramBlockDetailedConfig">
              <div class="defColor paramName">Started on:</div>
              <div class="detailedParamValue">
                {{ formattedSubscriptionStartDate }}
              </div>
            </div>

            <div
              v-if="$store.state.account.subscriptionData.Plan.name !== 'Free'"
              class="flexRow paramBlockDetailedConfig"
              style="align-items: flex-start"
            >
              <div class="defColor paramName">Expires on:</div>
              <div style="gap: 16px">
                <div class="detailedParamValue" style="white-space: nowrap">
                  {{ formattedSubscriptionExpiryDate }}
                </div>
                <div
                  class="medium_text link"
                  style="text-align: left"
                  @click="RenewSubscription"
                >
                  {{
                    endingInDays <= 0
                      ? "Plan Expired! Renew subscription"
                      : `Plan ending in ${endingInDays} days`
                  }}
                </div>
              </div>
            </div>
          </div>
        </div>
        <div v-else style="text-align: left">
          No active plan found.
          <span class="medium_text link" @click="UpgradeSubscription"
            >Upgrade</span
          >
        </div>
      </div>
    </div>
    <div class="flexRow">
      <button id="logoutButton" @click="logOut()">LOG OUT</button>
    </div>
  </div>
</template>

<script>
import { dateDefaultFormat } from "@/helpers/helpers";
import {
  getDateInShortMonthFormat,
  getDaysDifference,
} from "../../helpers/renderer";
import ShimmerEffect from "../Shimmer";

import qrcode from "qrcode-generator";

const sender = window.ipcSender;

export default {
  components: {
    ShimmerEffect,
  },
  data: function () {
    return {
      apiTimeout: null,
      isProcessing: false,
      isSubscriptionProcessing: false,
      accountShimmerItems: Array(4).fill(null),
    };
  },
  computed: {
    profileImage() {
      const profile = this.$store.state.account.userDetails.profile;
      return profile ? `https://api.privateline.io/uploads/${profile}` : "";
    },
    createdAt() {
      return this.$store.state.account.userDetails.createdAt;
    },
    formattedCreatedAt() {
      return getDateInShortMonthFormat(this.createdAt);
    },
    formattedSubscriptionExpiryDate() {
      return getDateInShortMonthFormat(
        this.$store.state.account.subscriptionData.expire_on
      );
    },
    formattedSubscriptionStartDate() {
      return getDateInShortMonthFormat(
        this.$store.state.account.subscriptionData.start_date
      );
    },
    endingInDays() {
      return getDaysDifference(
        this.$store.state.account.subscriptionData.expire_on
      );
    },
    IsAccountStateExists: function () {
      return this.$store.getters["account/isAccountStateExists"];
    },
    CurrentPlan: function () {
      return this.$store.state.account.accountStatus.CurrentPlan;
    },
    ActiveUntil: function () {
      return dateDefaultFormat(
        new Date(this.$store.state.account.accountStatus.ActiveUntil * 1000)
      );
    },
    IsActive: function () {
      return this.$store.state.account.accountStatus.Active;
    },
    IsCanUpgradeToPro: function () {
      return (
        this.IsAccountStateExists &&
        this.$store.state.account.accountStatus.Upgradable &&
        this.$store.state.account.accountStatus.CurrentPlan.toLowerCase() !=
          "privateLINE pro"
      );
    },
  },
  mounted() {
    // generating QRcode
    const typeNumber = 2;
    const errorCorrectionLevel = "M";
    const qr = qrcode(typeNumber, errorCorrectionLevel);

    let accId = "";
    if (
      this.$store.state.account != null &&
      this.$store.state.account.session != null &&
      this.$store.state.account.session.AccountID != null
    ) {
      accId = this.$store.state.account.session.AccountID;
    }

    qr.addData(accId);

    //this.accountStatusRequest();
    this.profileData();
    this.getSubscriptionData();
  },
  methods: {
    async logOut() {
      // check: is it is necessary to warn user about enabled firewall?
      let isNeedPromptFirewallStatus = false;
      if (this.$store.state.vpnState.firewallState.IsEnabled == true) {
        isNeedPromptFirewallStatus = true;
        if (
          this.$store.state.vpnState.firewallState.IsPersistent === false &&
          this.$store.state.settings.firewallDeactivateOnDisconnect === true &&
          this.$store.getters["vpnState/isDisconnected"] === false
        ) {
          isNeedPromptFirewallStatus = false;
        }
      }

      // show dialog ("confirm to logout")
      let needToDisableFirewall = true;
      let needToResetSettings = false;
      const mes = "Do you really want to log out privateLINE account?";
      const mesResetSettings = "Reset application settings to defaults";

      if (isNeedPromptFirewallStatus == true) {
        // LOGOUT message: Firewall is enabled
        let ret = await sender.showMessageBox(
          {
            type: "question",
            message: mes,
            detail:
              "The Firewall is enabled. All network access will be blocked.",
            checkboxLabel: mesResetSettings,
            buttons: ["Turn Firewall off and log out", "Log out", "Cancel"],
          },
          true
        );
        if (ret.response == 2) return; // cancel
        if (ret.response != 0) needToDisableFirewall = false;
        needToResetSettings = ret.checkboxChecked;
      } else {
        // LOGOUT message: Firewall is disabled
        let ret = await sender.showMessageBox(
          {
            type: "question",
            message: mes,
            checkboxLabel: mesResetSettings,
            buttons: ["Log out", "Cancel"],
          },
          true
        );
        if (ret.response == 1) return; // cancel
        needToResetSettings = ret.checkboxChecked;
      }

      // LOGOUT
      try {
        this.isProcessing = true;
        this.isSubscriptionProcessing = true;
        const isCanDeleteSessionLocally = true;
        await sender.Logout(
          needToResetSettings,
          needToDisableFirewall,
          isCanDeleteSessionLocally
        );
      } catch (e) {
        console.error(e);
      } finally {
        this.isProcessing = false;
        this.isSubscriptionProcessing = false;
      }
    },
    async accountStatusRequest() {
      await sender.SessionStatus();
    },
    async profileData() {
      try {
        this.isProcessing = true;

        this.apiTimeout = setTimeout(() => {
          throw Error("Profile API Time Out");
        }, 10 * 1000);
        await sender.ProfileData();
      } catch (err) {
        //TODO: show error on UI
        console.log({ err });
        sender.showMessageBoxSync({
          type: "error",
          buttons: ["OK"],
          message: "API Error",
          detail: `Profile data couldn't be fetched at this moment, please check your internet connection!`,
        });
      } finally {
        this.isProcessing = false;
        clearTimeout(this.apiTimeout);
        this.apiTimeout = null;
      }
    },

    async getSubscriptionData() {
      try {
        this.isSubscriptionProcessing = true;

        this.apiTimeout = setTimeout(() => {
          throw Error("Subscription API Time Out");
        }, 10 * 1000);
        await sender.SubscriptionData();
      } catch (err) {
        //TODO: show error on UI
        console.log({ err });
        sender.showMessageBoxSync({
          type: "error",
          buttons: ["OK"],
          message: "API Error",
          detail: `Subscription data couldn't be fetched at this momemnt, please check your internet connection!`,
        });
      } finally {
        this.isSubscriptionProcessing = false;
        clearTimeout(this.apiTimeout);
        this.apiTimeout = null;
      }
    },
    upgrade() {
      sender.shellOpenExternal(`https://www.account.privateline.io`);
    },
    addMoreTime() {
      sender.shellOpenExternal(`https://privateline.io/`);
    },
    RenewSubscription() {
      sender.shellOpenExternal(`https://account.privateline.io/billing`);
    },
    UpgradeSubscription() {
      sender.shellOpenExternal(`https://privateline.io/#pricing`);
    },
  },
};
</script>

<style scoped lang="scss">
@import "@/components/scss/constants";

.defColor {
  @extend .settingsDefaultTextColor;
}

.statusButton {
  border-radius: 4px;

  display: inline-block;

  font-weight: 500;
  font-size: 10px;
  line-height: 12px;
  letter-spacing: 1px;

  padding-top: 4px;
  padding-bottom: 4px;
  padding-left: 8px;
  padding-right: 8px;
}

.statusButtonActive {
  @extend .statusButton;
  background: rgba(177, 228, 125, 0.27);
  color: #64ad07;
}

.statusButtonNotActive {
  @extend .statusButton;
  background: rgba(228, 177, 125, 0.27);
  color: #ad6407;
}

.subscriptionDetails {
  margin-bottom: 40px;
}

.accountDescription * {
  font-size: 12px;
  line-height: 14px;
  letter-spacing: -0.4px;

  color: #3e6894;
}

.proAcountDescriptionBlock {
  @extend .accountDescription;
  background: rgba(57, 143, 230, 0.1);
  border-radius: 8px;
  padding-left: 14px;
  padding-right: 14px;
  padding-top: 7px;
  padding-bottom: 6px;
}

.accountDescription strong {
  font-weight: 600;
}

.accountDescription .i {
  color: #398fe6;
  display: inline;

  margin-left: 2px;
  margin-right: 4px;
}

.accountDescription div {
  margin-top: 6px;
}

#accountID {
  margin-top: 3px;
  margin-bottom: 7px;
}

#logoutButton {
  @extend .noBordersBtn;
  padding: 5px;
  margin-right: auto;
  margin-left: auto;

  font-weight: 500;
  font-size: 10px;
  line-height: 12px;

  letter-spacing: 1px;

  color: #8b9aab;
}

div.param {
  @extend .flexRow;
  margin-top: 3px;
}
div.paramBlockDetailedConfig {
  @extend .flexRow;
  margin-top: 2px;
}
.defColor {
  @extend .settingsDefaultTextColor;
}
div.paramName {
  min-width: 161px;
  max-width: 161px;
}
div.detailedParamValue {
  opacity: 0.7;
  overflow-wrap: break-word;
  -webkit-user-select: text;
  user-select: text;
  letter-spacing: 0.1px;
}
</style>
