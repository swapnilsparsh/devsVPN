<template>
  <div class="flexColumn" style="justify-content: space-between; width: 100%">
    <div class="flexColumn" style="gap: 2rem">
      <div class="flexRow">
        <div>
          <div class="settingsTitle">ACCOUNT DETAILS</div>
          <div class="flexRowSpace" style="align-items: flex-start">
            <div v-if="isProcessing || !this.IsSessionInfoReceived" class="flexColumn" style="gap: 10px">
              <ShimmerEffect :width="'100px'" :height="'100px'" :border-radius="'100%'" />
              <ShimmerEffect v-for="(item, index) in accountShimmerItems" :key="index" :width="'350px'"
                :height="'20px'" />
            </div>
            <div v-else-if="$store.state.account.userDetails.id" class="flexColumn">
              <div
                style="margin-bottom: 2rem"
                v-if="this.IsAccIdLogin"
                class="flexRow paramBlockDetailedConfig"
                title="Click to show or hide the account ID"
              >
                <label
                  class="settingsBigBoldFont selectable"
                  :class="{ blurred: isAccountIDBlurred }"
                >
                  {{ this.$store.state.account.session.AccountID }}
                </label>
                <div
                  @click="toggleAccountIDBlur"
                  style="cursor: pointer; margin-left: 10px"
                >
                  <div v-if="isAccountIDBlurred">
                    <img
                      style="vertical-align: middle"
                      src="@/assets/eye-close.svg"
                    />
                  </div>
                  <div v-if="!isAccountIDBlurred">
                    <img
                      style="vertical-align: middle"
                      src="@/assets/eye-open.svg"
                    />
                  </div>
                </div>
                <div style="display: inline-block">
                  <div style="display: inline-block">
                    <img
                      style="vertical-align: middle; cursor: pointer"
                      src="@/assets/copy.svg"
                      @click="copyAccountID"
                      alt="Copy"
                    />
                  </div>
                </div>
              </div>

              <div>
                <img v-if="!profileImage" src="@/assets/avtar.svg" style="height: 50px; width: 50px" />
                <img v-else :src="profileImage" style="
                    height: 50px;
                    width: 50px;
                    border-radius: 100%;
                    border: 5px solid #fff;
                    margin-bottom: 10px;
                  " />

                <div class="flexRow paramBlockDetailedConfig">
                  <div class="defColor paramName">Name:</div>
                  <div class="detailedParamValue">
                    {{ $store.state.account.userDetails.name }}
                  </div>
                </div>
                <div
                  v-if="!this.IsAccIdLogin"
                  class="flexRow paramBlockDetailedConfig"
                >
                  <div class="defColor paramName">Email:</div>
                  <div class="detailedParamValue">
                    {{ $store.state.account.userDetails.email }}
                  </div>
                </div>
                <div v-if="!this.IsAccIdLogin" class="flexRow paramBlockDetailedConfig">
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
            <div v-else>User profile data wasn't retrieved yet, please check later.</div>
            <!-- <div v-else>Api Error: Data couldn't be fetched at this moment.</div> -->
          </div>
        </div>
        <div v-if="this.IsSessionInfoReceived && this.IsAccIdLogin" class="overlay-container" style="margin: auto;" @click="toggleAccountIDBlur" title="Click to show or hide the account ID QR code">
          <div ref="accIdQrcodePlaceholder" :class="{ blurred: isAccountIDBlurred }"></div>
          <div v-if="isAccountIDBlurred" class="overlay">
            <svg xmlns="http://www.w3.org/2000/svg" width="32" fill="black" viewBox="0 0 512 512">
              <path
                d="M 36.01223241590214 59.49847094801223 Q 21.137614678899084 50.103975535168196 9.394495412844037 62.62996941896024 Q 0 77.5045871559633 12.525993883792049 89.24770642201835 L 475.98776758409787 452.50152905198775 L 475.98776758409787 452.50152905198775 Q 490.86238532110093 461.8960244648318 502.60550458715596 449.37003058103977 Q 512 434.4954128440367 499.47400611620793 422.7522935779817 L 417.27217125382265 358.5565749235474 L 417.27217125382265 358.5565749235474 Q 439.97553516819573 334.28746177370033 455.6330275229358 309.2354740061162 Q 471.2905198776758 284.9663608562691 479.9021406727829 265.39449541284404 Q 483.0336391437309 256 479.9021406727829 246.60550458715596 Q 470.50764525993884 224.68501529051989 452.50152905198775 197.28440366972478 Q 434.4954128440367 169.88379204892968 407.0948012232416 144.04892966360856 Q 378.91131498470946 117.43119266055047 341.3333333333333 99.42507645259938 Q 303.75535168195717 81.41896024464832 256 80.63608562691131 Q 216.07339449541286 81.41896024464832 182.40978593272172 93.94495412844037 Q 149.5290519877676 107.25382262996942 123.69418960244649 128.3914373088685 L 36.01223241590214 59.49847094801223 L 36.01223241590214 59.49847094801223 Z M 180.0611620795107 173.01529051987768 Q 211.37614678899084 144.04892966360856 256 143.26605504587155 Q 303.75535168195717 144.83180428134557 335.8532110091743 176.14678899082568 Q 367.16819571865443 208.2446483180428 368.73394495412845 256 Q 368.73394495412845 285.7492354740061 355.4250764525994 310.0183486238532 L 324.8929663608563 286.5321100917431 L 324.8929663608563 286.5321100917431 Q 335.0703363914373 263.04587155963304 328.8073394495413 236.42813455657492 Q 321.76146788990826 212.15902140672782 302.9724770642202 197.28440366972478 Q 283.40061162079513 182.40978593272172 259.13149847094803 180.8440366972477 Q 252.085626911315 182.40978593272172 253.651376146789 190.23853211009174 Q 256 197.28440366972478 256 205.8960244648318 Q 256 218.42201834862385 250.51987767584097 227.8165137614679 L 180.0611620795107 173.01529051987768 L 180.0611620795107 173.01529051987768 Z M 297.49235474006116 360.9051987767584 Q 277.9204892966361 368.73394495412845 256 368.73394495412845 Q 208.2446483180428 367.16819571865443 176.14678899082568 335.8532110091743 Q 144.83180428134557 303.75535168195717 143.26605504587155 256 Q 143.26605504587155 248.17125382262998 144.04892966360856 240.34250764525993 L 70.45871559633028 182.40978593272172 L 70.45871559633028 182.40978593272172 Q 43.84097859327217 218.42201834862385 32.88073394495413 246.60550458715596 Q 28.966360856269112 256 32.88073394495413 265.39449541284404 Q 41.49235474006116 287.31498470948014 59.49847094801223 314.7155963302752 Q 77.5045871559633 342.11620795107035 105.68807339449542 367.9510703363914 Q 133.0886850152905 394.56880733944956 170.66666666666666 412.5749235474006 Q 208.2446483180428 430.5810397553517 256 431.3639143730887 Q 312.3669724770642 429.79816513761466 354.64220183486236 406.3119266055046 L 297.49235474006116 360.9051987767584 L 297.49235474006116 360.9051987767584 Z" />
            </svg>
          </div>
        </div>
      </div>

      <div>
        <div class="settingsTitle">SUBSCRIPTION DETAILS</div>
        <div v-if="$store.state.account.subscriptionData != null" class="flexRowSpace" style="align-items: flex-start">
          <div v-if="isSubscriptionProcessing" class="flexColumn" style="gap: 10px">
            <ShimmerEffect :width="'350px'" :height="'20px'" />
            <ShimmerEffect :width="'350px'" :height="'20px'" />
            <ShimmerEffect :width="'350px'" :height="'20px'" />
          </div>
          <div v-else-if="$store.state.account.subscriptionData.Plan" class="flexColumn" style="width: 100%">
            <div class="flexRow paramBlockDetailedConfig">
              <div class="defColor paramName">Plan Name:</div>
              <div class="flexRow" style="gap: 16px">
                <div class="detailedParamValue">
                  {{ $store.state.account.subscriptionData.Plan.name }}
                </div>
                <div v-if="
                  $store.state.account.subscriptionData.Plan.name === 'Free'
                " class="medium_text link" @click="UpgradeSubscription">
                  Upgrade
                </div>
              </div>
            </div>

            <div v-if="$store.state.account.subscriptionData.Plan.name === 'Group'"
              class="flexRow paramBlockDetailedConfig">
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

            <div v-if="$store.state.account.subscriptionData.Plan.name !== 'Free'"
              class="flexRow paramBlockDetailedConfig" style="align-items: flex-start">
              <div class="defColor paramName">Expires on:</div>
              <div style="gap: 16px">
                <div class="detailedParamValue" style="white-space: nowrap">
                  {{ formattedSubscriptionExpiryDate }}
                </div>
                <div class="medium_text link" style="text-align: left" @click="RenewSubscription">
                  {{
                    endingInDays <= 0 ? "Plan Expired! Renew subscription" : `Plan ending in ${endingInDays} days` }}
                    </div>
                </div>
              </div>
            </div>
          </div>
          <div v-else style="text-align: left">
            No active plan found.
            <span class="medium_text link" @click="UpgradeSubscription">Upgrade</span>
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
      apiProfileTimeout: null,
      apiSubscriptionTimeout: null,
      isProcessing: true,
      isSubscriptionProcessing: true,
      accountShimmerItems: Array(4).fill(null),
      isAccountIDBlurred: true,
      acctIdQRCodeSvg: "",
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
    IsSessionInfoReceived: function () {
      return this.$store.state.account.session.SessionInfoReceived;
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
        const accountIdPattern = /^([1-9A-HJ-NP-Z]{4}-){2}[1-9A-HJ-NP-Z]{4}$/;
        value = accountIdPattern.test(accountId);
      }

      return value;
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
    //this.accountStatusRequest();
    this.profileData();
    this.getSubscriptionData();
    this.waitForSessionInfo();
  },
  methods: {
    toggleAccountIDBlur() {
      this.isAccountIDBlurred = !this.isAccountIDBlurred;
    },
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
        this.acctIdQRCodeSvg = "";
      }
    },
    async accountStatusRequest() {
      await sender.SessionStatus();
    },
    async waitForSessionInfo() {
      // wait for 10s for session information to come through
      for (let i = 0; !this.IsSessionInfoReceived && i < 40; i++) {
        await new Promise(r => setTimeout(r, 250));
      }

      // if session info received - trigger rendering account ID QR code
      if (this.IsSessionInfoReceived)
        this.computeAndSetAccIdQrCode();
      else
        console.log("waitForSessionInfo() timed out")
    },
    async profileData() {
      try {
        this.isProcessing = true;

        this.apiProfileTimeout = setTimeout(() => {
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
        clearTimeout(this.apiProfileTimeout);
        this.apiProfileTimeout = null;
      }
    },

    async getSubscriptionData() {
      try {
        this.isSubscriptionProcessing = true;

        this.apiSubscriptionTimeout = setTimeout(() => {
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
          detail: `Subscription data couldn't be fetched at this moment, please check your internet connection!`,
        });
      } finally {
        this.isSubscriptionProcessing = false;
        clearTimeout(this.apiSubscriptionTimeout);
        this.apiSubscriptionTimeout = null;
      }
    },
    computeAndSetAccIdQrCode() {
      if (!this.IsAccIdLogin)
          return;

      // generating QRcode
      if (this.acctIdQRCodeSvg === "") {
        const typeNumber = 2;
        const errorCorrectionLevel = "M";
        const qr = qrcode(typeNumber, errorCorrectionLevel);

        let accId = this.$store.state.account.session.AccountID;
        qr.addData(accId);
        qr.make();
        this.acctIdQRCodeSvg = qr.createSvgTag(3, 10);
      }

      if (this.$refs.accIdQrcodePlaceholder && this.acctIdQRCodeSvg !== "") {
        this.$refs.accIdQrcodePlaceholder.innerHTML = this.acctIdQRCodeSvg;
        // this.$refs.accIdQrcodePlaceholder.getElementsByTagName("svg")[0].style.width = "100%";
        // this.$refs.accIdQrcodePlaceholder.getElementsByTagName("svg")[0].style.height = "100%";
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
    copyAccountID() {
      const accountId = this.$store.state.account.session.AccountID;
      const tempInput = document.createElement("input");

      document.body.appendChild(tempInput);
      tempInput.value = accountId;
      tempInput.select();
      document.execCommand("copy");
      document.body.removeChild(tempInput);
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

// Blur effect for the QR code
.blurred {
  filter: blur(5px);
  /* Adjust the blur radius as needed */
  transition: filter 0.3s ease;
  /* Smooth transition for the blur effect */
}

.overlay-container {
  position: relative;
  display: inline-block;
  cursor: pointer;
}

// QR code overlay
.overlay {
  position: absolute;
  top: 50%;
  left: 50%;
  transform: translate(-50%, -50%);
  background-color: rgba(255, 255, 255, 0.5);
  padding: 5px 5px 2px 5px;
  border-radius: 4px;
}
</style>
