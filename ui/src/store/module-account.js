const oneDay = 24 * 60 * 60 * 1000; // hours*minutes*seconds*milliseconds

export default {
  namespaced: true,

  // STATE
  state: {
    //userData
    userDetails: {},

    // Session info
    session: {
      AccountID: "",
      Session: "",
      DeviceName: "",
      WgPublicKey: "",
      WgLocalIP: "",
      WgUsePresharedKey: false,
      WgKeyGenerated: new Date(),
      WgKeysRegenIntervalSec: 0,
    },
    accountStatus: {
      Active: false,
      ActiveUntil: 0,
      CurrentPlan: "",
      PaymentMethod: "",
      IsRenewable: false,
      WillAutoRebill: false,
      IsFreeTrial: false,
      Capabilities: [],
      Upgradable: false,
      UpgradeToPlan: "",
      UpgradeToURL: "",
      DeviceManagement: false,
      DeviceManagementURL: "", // applicable for 'session limit' error
      Limit: 0, // applicable for 'session limit' error
    },
  },

  mutations: {
    userDetails(state, userData) {
      state.userDetails = userData;
    },
    session(state, sessionInfo) {
      state.session = sessionInfo;

      // erase account state
      if (
        !state.accountStatus ||
        !state.session ||
        state.accountStatus.SessionTokenLastPart !==
          getLastPartOfSessionToken(state.session.Session)
      )
        state.accountStatus = null;
    },
    sessionStatus(state, accState) {
      if (
        accState == null ||
        accState.Account == null ||
        (state.session &&
          state.session.Session &&
          accState.SessionToken !== state.session.Session)
      )
        return;

      state.session.DeviceName = accState.DeviceName;
      state.accountStatus = accState.Account;

      // save session for account status object
      // (to be sure that account info belongs to correct session)
      if (accState.SessionToken)
        state.accountStatus.SessionTokenLastPart = getLastPartOfSessionToken(
          accState.SessionToken
        );

      // convert capabilities to lower case
      if (state.accountStatus.Capabilities != null)
        state.accountStatus.Capabilities.map((a) => {
          return a.toLowerCase();
        });
    },
  },

  getters: {
    isLoggedIn: (state) => !!state.session.Session,

    isAccountStateExists: (state) => {
      return state.accountStatus != null;
    },

    isMultihopAllowed: (state) => {
      // if no info about account status - let's believe that multihop is allowed
      if (!state.accountStatus || !state.accountStatus.Capabilities)
        return true;
      return state.accountStatus.Capabilities.includes("multihop");
    },

    messageFreeTrial: (state) => {
      if (!state.accountStatus) return null;
      if (!state.accountStatus.IsFreeTrial) return null;

      const expirationDate = new Date(state.accountStatus.ActiveUntil * 1000);
      const currDate = new Date();
      var diffDays = Math.round((expirationDate - currDate) / oneDay);

      if (diffDays < 0 || state.accountStatus.Active === false)
        return "Your free trial has expired";
      if (state.accountStatus.WillAutoRebill === true) return null;

      if (diffDays == 0) return "Your free trial expires today";
      if (diffDays == 1) return "Your free trial expires in 1 day";
      return `Your free trial expires in ${diffDays} days`;
    },
    messageAccountExpiration: (state) => {
      if (!state.accountStatus) return null;
      if (state.accountStatus.IsFreeTrial) return null;

      const expirationDate = new Date(state.accountStatus.ActiveUntil * 1000);
      const currDate = new Date();
      var diffDays = Math.round((expirationDate - currDate) / oneDay);
      if (diffDays > 3) return null;

      if (diffDays < 0 || state.accountStatus.Active === false)
        return "Your subscription has expired";
      if (state.accountStatus.WillAutoRebill === true) return null;

      if (diffDays == 0) return "Your account expires today";
      if (diffDays == 1) return "Your account expires in 1 day";
      return `Your account expires in ${diffDays} days`;
    },
  },

  actions: {
    sessionStatus(context, val) {
      context.commit("sessionStatus", val);

      if (context.getters.isMultihopAllowed === false)
        // TODO: have to be removed from here (potential problem example: VPN is connected multihop but multihop not allowed)
        context.dispatch("settings/isMultiHop", false, { root: true });
    },
  },

  modules: {},
};

function getLastPartOfSessionToken(sessionToken) {
  if (!sessionToken || sessionToken.length < 6) return "";
  return sessionToken.substr(sessionToken.length - 6);
}
