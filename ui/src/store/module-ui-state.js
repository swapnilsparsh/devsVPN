export default {
  namespaced: true,

  state: {
    isParanoidModePasswordView: false,

    // favorite servers view selected
    serversFavoriteView: false,

    currentSettingsViewName: null, // 'account', 'general', 'version' ...

    isIPv6View: false,

    isPauseResumeInProgress: false,
    //{
    //  state: AppUpdateStage.Downloading,
    //  error: null,
    //  readyToInstallBinary: "",
    //  readyToInstallSignatureFile: "",
    //  downloadStatus: {
    //    contentLength: 0,
    //    downloaded:    0
    //  }
    //}
    appUpdateProgress: null,

    // if not empty, then UI settings view will show this message 
    // (e.g. message text about the Location Services permission required for ability to get WiFi info)
    wifiWarningMessage: "",
  },

  mutations: {
    isParanoidModePasswordView(state, value) {
      state.isParanoidModePasswordView = value;
    },
    serversFavoriteView(state, value) {
      state.serversFavoriteView = value;
    },
    appUpdateProgress(state, value) {
      state.appUpdateProgress = value;
    },
    currentSettingsViewName(state, value) {
      state.currentSettingsViewName = value;
    },
    isIPv6View(state, value) {
      state.isIPv6View = value;
    },
    isPauseResumeInProgress(state, value) {
      state.isPauseResumeInProgress = value;
    },
    wifiWarningMessage(state, value) {
      state.wifiWarningMessage = value;
    },
  },

  // can be called from renderer
  actions: {
    isParanoidModePasswordView(context, value) {
      context.commit("isParanoidModePasswordView", value);
    },
    serversFavoriteView(context, value) {
      context.commit("serversFavoriteView", value);
    },
    currentSettingsViewName(context, value) {
      context.commit("currentSettingsViewName", value);
    },
    isIPv6View(context, value) {
      context.commit("isIPv6View", value);
    },
  },
};
