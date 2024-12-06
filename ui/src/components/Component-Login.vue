<template>
  <div class="flexColumn">
    <div class="flexRow flexRowRestSpace">
      <spinner :loading="isProcessing" />

      <div class="column">
        <div class="centered" style="margin-top: -50px; margin-bottom: 50px">
          <img width=" 70%" src="@/assets/logo.svg" />
        </div>

        <div>
          <!-- ACCOUNT ID -->
          <div class="centered">
            <div class="large_text">Login</div>
            <div class="medium_text">to privateLINE Connect</div>
            <div style="height: 12px" />
          </div>

          <div style="height: 21px" />
          <div v-if="isAccountIdLogin" style="position: relative; display: flex; align-items: center">
            <input ref="accountid" v-model="accountID" class="styledBig" style="text-align: left"
              placeholder="Account ID a-XXXX-XXXX-XXXX" :type="passwordType" @keyup="keyup($event)" />
            <img v-if="showPassword" src="@/assets/eye-close.svg" alt="Eye Image" style="
                width: 20px;
                height: 20px;
                position: absolute;
                right: 10px;
                cursor: pointer;
              " @click="toggleEye" />
            <img v-else src="@/assets/eye-open.svg" alt="Eye Image" style="
                width: 20px;
                height: 20px;
                position: absolute;
                right: 10px;
                cursor: pointer;
              " @click="toggleEye" />

          </div>

          <!--
          <input v-if="!isAccountIdLogin" ref="email" v-model="email" class="styledBig" style="text-align: left"
            placeholder="Enter your email" @keyup="keyup($event)" />

          <div style="height: 10px" />
          <div v-if="!isAccountIdLogin" style="position: relative; display: flex; align-items: center">
            <input ref="password" v-model="password" class="styledBig" style="text-align: left"
              placeholder="Enter your Password" :type="passwordType" @keyup="keyup($event)" />
            <img v-if="showPassword" src="@/assets/eye-close.svg" alt="Eye Image" style="
                width: 20px;
                height: 20px;
                position: absolute;
                right: 10px;
                cursor: pointer;
              " @click="toggleEye" />
            <img v-else src="@/assets/eye-open.svg" alt="Eye Image" style="
                width: 20px;
                height: 20px;
                position: absolute;
                right: 10px;
                cursor: pointer;
              " @click="toggleEye" />
          </div>
          -->
        </div>

        <!--
        <div v-if="!isAccountIdLogin" class="medium_text link" @click="ForgotPassword">
          Forgot Password?
        </div>
        -->

        <div style="height: 24px" />
        <button class="master" @click="Login">Log In With Account ID</button>
        <div style="height: 12px" />
        <!--
        <button v-if="!isAccountIdLogin" class="slave" v-on:click="onLoginWithAccountId">Login With Account ID</button>
        <button v-if="isAccountIdLogin" class="slave" v-on:click="onLoginWithAccountId">Login With Email And
          Password</button>
        <div style="height: 12px" />
        -->
        <button class="slave" v-on:click="openSSO">SSO Login</button>
        <div style="height: 12px" />
        <button class="slave" @click="CreateAccount">Create an account</button>
      </div>
    </div>

    <!-- <div class="flexRow leftright_margins" style="margin-bottom: 20px">
      <div
        class="flexRow flexRowRestSpace switcher_small_text"
        style="margin-right: 10px"
      >
        {{ firewallStatusText }}
      </div>

      <SwitchProgress
        :onChecked="firewallOnChecked"
        :isChecked="this.$store.state.vpnState.firewallState.IsEnabled"
        :isProgress="firewallIsProgress"
      />
    </div> -->
  </div>
</template>

<script>
import spinner from "@/components/controls/control-spinner.vue";
import SwitchProgress from "@/components/controls/control-switch-small2.vue";

import { IsOsDarkColorScheme } from "@/helpers/renderer";
import { ColorTheme } from "@/store/types";

const sender = window.ipcSender;
const ipcRenderer = sender.GetSafeIpcRenderer();
import {
  API_SUCCESS,
  API_SESSION_LIMIT,
  API_CAPTCHA_REQUIRED,
  API_CAPTCHA_INVALID,
  API_2FA_REQUIRED,
  API_2FA_TOKEN_NOT_VALID,
} from "@/api/statuscode";

function processError(e) {
  console.error(e);
  sender.showMessageBox({
    type: "error",
    buttons: ["OK"],
    message: e.toString(),
  });
}

export default {
  components: {
    spinner,
    SwitchProgress,
  },
  props: {
    forceLoginAccount: {
      type: String,
      default: null,
    },
  },
  data: function () {
    return {
      firewallIsProgress: false,

      password: "",
      isProcessing: false,
      isAccountIdLogin: true,
      accountID: '',

      rawResponse: null,
      apiResponseStatus: 0,

      capchaImageStyle: "",

      isForceLogoutRequested: false,
      captcha: "",
      confirmation2FA: "",
      showPassword: false,
    };
  },
  computed: {
    passwordType() {
      return this.showPassword ? "text" : "password";
    },

    isCaptchaRequired: function () {
      return (
        (this.apiResponseStatus === API_CAPTCHA_REQUIRED ||
          this.apiResponseStatus === API_CAPTCHA_INVALID) &&
        this.captchaImage &&
        this.captchaID &&
        this.accountID
      );
    },
    isCaptchaInvalid: function () {
      return this.apiResponseStatus === API_CAPTCHA_INVALID;
    },
    is2FATokenRequired: function () {
      return (
        (this.apiResponseStatus === API_2FA_REQUIRED ||
          this.apiResponseStatus === API_2FA_TOKEN_NOT_VALID) &&
        this.accountID
      );
    },
    captchaImage: function () {
      return this.rawResponse?.captcha_image;
    },
    captchaID: function () {
      return this.rawResponse?.captcha_id;
    },
    firewallStatusText: function () {
      if (this.$store.state.vpnState.firewallState.IsEnabled)
        return "Firewall enabled and blocking all traffic";
      return "Firewall disabled";
    },
  },
  watch: {
    isCaptchaRequired() {
      if (!this.$refs.captcha || !this.$refs.accountid) return;
      if (this.isCaptchaRequired) this.$refs.captcha.focus();
      else this.$refs.accountid.focus();
    },
  },
  mounted() {
    /*listening for 'sso-auth' event trigerred from background.js which send auth 'code'*/
    ipcRenderer.on("sso-auth", async (event, authData) => {
      try {
        this.isProcessing = true;
        await sender.SsoLogin(authData?.code, authData?.session_state);
        console.log("calling SsoLogin with this param --->", authData?.code);
      } catch (error) {
        console.log(error.message);
      } finally {
        this.isProcessing = false;
      }
    });

    // COLOR SCHEME
    window.matchMedia("(prefers-color-scheme: dark)").addListener(() => {
      this.updateColorScheme();
    });
    this.updateColorScheme();

    if (this.$refs.accountid) this.$refs.accountid.focus();

    let stateParams = history.state.params;
    history.replaceState({}, ""); // clear state params to avoid re-login on page refresh

    if (stateParams && stateParams.forceLoginAccount != null) {
      this.accountID = stateParams.forceLoginAccount;

      let confirmation2FA = null;
      if (stateParams.extraArgs) {
        confirmation2FA = stateParams.extraArgs.confirmation2FA;
      }

      const force = true;
      this.Login(force, confirmation2FA);
    } else {
      if (this.$store.state.settings.isExpectedAccountToBeLoggedIn === true) {
        this.$store.dispatch("settings/isExpectedAccountToBeLoggedIn", false);
        setTimeout(() => {
          sender.showMessageBox({
            type: "info",
            buttons: ["OK"],
            message: `You are logged out.\n\nYou have been redirected to the login page to re-enter your credentials.`,
          });
        }, 0);
      }
    }
  },
  methods: {
    toggleEye() {
      // Toggle the state
      this.showPassword = !this.showPassword;
    },
    async Login(isForceLogout, confirmation2FA) {
      try {
        //console.log("accountID:", this.accountID)
        // check accountID
        // var pattern = new RegExp("^([a-zA-Z0-9]{7,8})$"); // fragment locator
        // if (this.accountID) this.accountID = this.accountID.trim();
        // if (pattern.test(this.accountID) !== true) {
        //   throw new Error(
        //     "Your account ID has to be in 'XXXXXXXX' format. You can find it on other devices where you are logged in and in the client area of the PrivateLINE website."
        //   );
        // }

        // if (this.is2FATokenRequired && !this.confirmation2FA) {
        //   sender.showMessageBoxSync({
        //     type: "warning",
        //     buttons: ["OK"],
        //     message: "Failed to login",
        //     detail: `Please enter 6-digit verification code`,
        //   });
        //   return;
        // }

        this.isProcessing = true;
        if (this.isAccountIdLogin) {
          const pattern = new RegExp("^a-([1-9A-HJ-NP-Z]{4}-){2}[1-9A-HJ-NP-Z]{4}$");
          if (this.accountID) this.accountID = this.accountID.trim();
          if (!pattern.test(this.accountID)) {
            throw new Error(
              "Invalid account ID. Your account ID has to be in 'a-XXXX-XXXX-XXXX' format. Please check your account ID and try again."
            );
          }
        } else {
          if (
            !(this.email != undefined && this.email != null && this.email != "")
          ) {
            sender.showMessageBoxSync({
              type: "error",
              buttons: ["OK"],
              message: "Failed to login",
              detail: `Please enter email address`,
            });
            return;
          }
          if (
            !(
              this.password != undefined &&
              this.password != null &&
              this.password != ""
            )
          ) {
            sender.showMessageBoxSync({
              type: "error",
              buttons: ["OK"],
              message: "Failed to login",
              detail: `Please enter password`,
            });
            return;
          }
        }

        const resp = await sender.Login(
          this.isAccountIdLogin ? this.accountID : this.email,
          this.isAccountIdLogin ? "" : this.password
          // isForceLogout === true || this.isForceLogoutRequested === true,
          // this.captchaID,
          // this.captcha,
          // confirmation2FA ? confirmation2FA : this.confirmation2FA
        );

        //console.log("resp", resp);
        //const accountInfoResponse = await sender.AccountInfo();
        //console.log("accountInfoResponse", accountInfoResponse);

        if (resp.APIStatus === 426) {
          sender.showMessageBoxSync({
            type: "error",
            buttons: ["OK"],
            message: "Failed to login",
            detail:
              "We are sorry - we are unable to add an additional device to your account, because you already registered a maximum of N devices possible under your current subscription. You can go to your device list on our website (https://account.privateline.io/pl-connect/page/1) and unregister some of your existing devices from your account, or you can upgrade your subscription at https://privateline.io/order in order to be able to use more devices.",
          });
        } else if (resp.APIStatus === 412) {
          sender.showMessageBoxSync({
            type: "error",
            buttons: ["OK"],
            message: "Failed to login",
            detail:
              "We are sorry - your free account only allows to use one device. You can upgrade your subscription at https://privateline.io/order in order to be able to use more devices.",
          });
        } else if (resp.APIErrorMessage == "Device limit of 5 reached") {
          sender.showMessageBoxSync({
            type: "error",
            buttons: ["OK"],
            message: "Failed to login",
            detail:
              resp.APIErrorMessage +
              "\n\nYou can remove the device from your privateLINE account and try again.",
          });
        } else if (resp.APIErrorMessage != "") {
          sender.showMessageBoxSync({
            type: "error",
            buttons: ["OK"],
            message: "Failed to login",
            detail: 
              resp.APIErrorMessage +
              "\n\nIf you don't have a privateLINE account yet, you can create one at https://account.privateline.io/sign-in",
          });
        }

        // this.isForceLogoutRequested = false;

        // const oldConfirmation2FA = this.confirmation2FA;
        // this.captcha = "";
        // this.confirmation2FA = "";
        // this.apiResponseStatus = resp.APIStatus;
        // this.rawResponse = JSON.parse(resp.RawResponse);

        // if (resp.APIStatus !== API_SUCCESS) {
        //   if (resp.APIStatus === API_CAPTCHA_INVALID) {
        //     throw new Error(`Invalid captcha, please try again`);
        //   } else if (resp.APIStatus === API_CAPTCHA_REQUIRED) {
        //     // UI should be updated automatically based on data from 'resp.RawResponse'
        //     this.isForceLogoutRequested = isForceLogout;
        //   } else if (resp.APIStatus === API_2FA_TOKEN_NOT_VALID) {
        //     throw new Error(
        //       `Specified two-factor authentication token is not valid`
        //     );
        //   } else if (resp.APIStatus === API_2FA_REQUIRED) {
        //     // UI should be updated automatically based on data from 'resp.RawResponse'
        //     this.isForceLogoutRequested = isForceLogout;
        //   } else if (
        //     resp.APIStatus === API_SESSION_LIMIT &&
        //     resp.Account != null
        //   ) {
        //     this.$router.push({
        //       name: "AccountLimit",
        //       state: {
        //         params: {
        //           accountID: this.accountID,
        //           devicesMaxLimit: resp.Account.Limit,
        //           CurrentPlan: resp.Account.CurrentPlan,
        //           PaymentMethod: resp.Account.PaymentMethod,
        //           Upgradable: resp.Account.Upgradable,
        //           UpgradeToPlan: resp.Account.UpgradeToPlan,
        //           UpgradeToURL: resp.Account.UpgradeToURL,
        //           DeviceManagement: resp.Account.DeviceManagement,
        //           DeviceManagementURL: resp.Account.DeviceManagementURL,
        //           extraArgs: {
        //             confirmation2FA: oldConfirmation2FA,
        //           },
        //         },
        //       },
        //     });
        //   } else throw new Error(`[${resp.APIStatus}] ${resp.APIErrorMessage}`);
        // } else {
        //   try {
        //     await sender.GeoLookup();
        //   } catch (e) {
        //     console.error(e);
        //   }
        // }
      } catch (e) {
        console.error(e);
        sender.showMessageBoxSync({
          type: "error",
          buttons: ["OK"],
          message: "Failed to login",
          detail: `${e}`,
        });
      } finally {
        this.isProcessing = false;
      }
    },
    CreateAccount() {
      sender.shellOpenExternal(`https://account.privateline.io/sign-in`);
    },
    openSSO() {
      sender.shellOpenExternal(
        `https://sso.privateline.io/realms/privateLINE/protocol/openid-connect/auth?client_id=pl-connect-desktop&response_type=code&redirect_uri=privateline://auth`);
    },
    onLoginWithAccountId() {
      this.isAccountIdLogin = !this.isAccountIdLogin;
    },
    ForgotPassword() {
      sender.shellOpenExternal(
        `https://sso.privateline.io/realms/privateLINE/login-actions/reset-credentials`
      );
    },
    Cancel() {
      this.rawResponse = null;
      this.apiResponseStatus = 0;
      this.captcha = "";
      this.confirmation2FA = "";
      this.isForceLogoutRequested = false;
    },
    keyup(event) {
      if (event.keyCode === 13) {
        // Cancel the default action, if needed
        event.preventDefault();
        this.Login();
      }
    },
    updateColorScheme() {
      let isDarkTheme = false;
      let scheme = sender.ColorScheme();
      if (scheme === ColorTheme.system) {
        isDarkTheme = IsOsDarkColorScheme();
      } else isDarkTheme = scheme === ColorTheme.dark;

      if (isDarkTheme)
        this.capchaImageStyle =
          "filter: grayscale(100%) brightness(0%) invert(100%); display: block; margin-left: auto; margin-right: auto; max-width:240px; max-height:80px";
      else
        this.capchaImageStyle =
          "filter: grayscale(100%) brightness(0%); display: block; margin-left: auto; margin-right: auto; max-width:240px; max-height:80px";
    },
    async firewallOnChecked(isEnabled) {
      this.firewallIsProgress = true;
      try {
        if (
          isEnabled === false &&
          this.$store.state.vpnState.firewallState.IsPersistent
        ) {
          let ret = await sender.showMessageBoxSync(
            {
              type: "question",
              message:
                "The always-on firewall is enabled. If you disable the firewall the 'always-on' feature will be disabled.",
              buttons: ["Disable Always-on firewall", "Cancel"],
            },
            true
          );

          if (ret == 1) return; // cancel
          await sender.KillSwitchSetIsPersistent(false);
        }

        this.firewallIsProgress = true;
        await sender.EnableFirewall(isEnabled);
      } catch (e) {
        processError(e);
      } finally {
        this.firewallIsProgress = false;
      }
    },
  },
};
</script>

<!-- Add "scoped" attribute to limit CSS to this component only -->
<style scoped lang="scss">
@import "@/components/scss/constants";

.leftright_margins {
  margin-left: 20px;
  margin-right: 20px;
}

.column {
  @extend .leftright_margins;
  width: 100%;
}

.centered {
  margin-top: auto;
  margin-bottom: auto;
  text-align: center;
}

.large_text {
  font-weight: 600;
  font-size: 18px;
  line-height: 120%;
}

.small_text {
  font-size: 13px;
  line-height: 17px;
  letter-spacing: -0.208px;
  color: #98a5b3;
}

.switcher_small_text {
  font-size: 11px;
  line-height: 13px;
  color: var(--text-color-details);
}
</style>
