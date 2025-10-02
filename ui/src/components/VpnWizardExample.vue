<template>
  <div class="example-container">
    <!-- Example buttons to trigger different wizard configurations -->
    <!--
    <h2>VPN Wizard Usage Examples</h2>

    <div class="example-buttons">
      <button class="master example-btn" @click="openFullWizard">
        Open Full Wizard
      </button>

      <button class="slave example-btn" @click="openAutoReconfigOnly">
        Auto-reconfig Only
      </button>

      <button class="slave example-btn" @click="openNordVPNOnly">
        NordVPN Instructions Only
      </button>

      <button class="slave example-btn" @click="openFinalInstructionsOnly">
        Final Instructions Only
      </button>
    </div>
    -->

    <!-- 
      :introDescr="this.$store.state.uiState.vpnWizard.introDescr"
      :autoReconfigAvailable="this.$store.state.uiState.vpnWizard.showAutoReconfigVpnStep"
      :nordVPNWindows="this.$store.state.uiState.vpnWizard.showNordVpnWindowsStep"
    -->
    <!-- VPN Wizard Component -->
    <VpnWizard
      :endOfFlowParam="false"
      @wizard-closed="onWizardClosed"
      @wizard-completed="onWizardCompleted"
      @step-changed="onStepChanged"
    >
      <!-- Custom content slots (optional) -->

      <!-- intro screen -->
      <!-- <template #intro-screen-content>
        <div class="step-content">
          <div class="info-box">
            <p><strong>Other VPNs detected, that may be blocking privateLINE connectivity</strong></p>
              FIXME: Vlad - list other VPNs in a bullet list
          </div>
        </div>
      </template> -->
      
      <!-- <template #nordvpn-content>
        <div class="custom-content">
        </div>
      </template> -->     

      <template #auto-reconfig-content>
        <div class="custom-content">
          <!-- <h4>Custom Auto-reconfig Content</h4>
          <p>
            This is custom content for the auto-reconfig step. You can put any
            Vue template content here.
          </p> -->
          <div class="action-buttons">
            <button class="master small-btn" @click="performAutoReconfig">
              Auto Reconfigure Other VPNs Once
            </button>
          </div>
          <input type="checkbox" id="SetVpnCoexistPermissionCheckbox" v-model="toSetVpnCoexistPermission" />
          <label for="SetVpnCoexistPermissionCheckbox">Give PL Connect permission to reconfigure other VPNs automatically when needed
             (you can disable it later in Settings)</label>
        </div>
      </template>

      <!-- The error message is shown in final instructions screen only if error was recorded -->
      <template v-if="this.autoReconfigFailed" #final-instructions-content>
        <div class="custom-error-content">
          <h3>⚠️ {{this.autoReconfigErrHeader}}</h3>
          <div class="action-buttons">
            <button class="master small-btn" @click="onSendVpnWizardLogs">
              Send Error Logs To privateLINE
            </button>
          </div>

          <div class="margin-top">
            <div class="info-box">
              <p>{{this.autoReconfigErrDetails}}</p>
            </div>
        </div>
        </div>
      </template>
    </VpnWizard>
  </div>
</template>

<script>
import VpnWizard from "./VpnWizard.vue";

const sender = window.ipcSender;

export default {
  name: "VpnWizardExample",
  components: {
    VpnWizard,
  },
  data() {
    return {
      showWizard: false,
      toSetVpnCoexistPermission: this.hasPermissionToReconfigureOtherVPNs,
      reconnectIssued: false,
      autoReconfigFailed: false,
      autoReconfigErrHeader: "",
      autoReconfigErrDetails: "",
      // wizardConfig: {
      //   endOfFlowParam: false,
      //   autoReconfigAvailable: false,
      //   nordVPNWindows: false,
      // },
      nordvpnSteps: [
        "Open NordVPN application from your system tray",
        "Navigate to Settings → Advanced",
        'Disable "Kill Switch" feature temporarily',
        "Disconnect from any active NordVPN connection",
        "Close NordVPN application completely",
      ],
    };
  },
  methods: {
    // openFullWizard() {
    //   this.wizardConfig = {
    //     endOfFlowParam: false,
    //     autoReconfigAvailable: true,
    //     nordVPNWindows: true,
    //   };
    //   this.showWizard = true;
    // },

    // openAutoReconfigOnly() {
    //   this.wizardConfig = {
    //     endOfFlowParam: false,
    //     autoReconfigAvailable: true,
    //     nordVPNWindows: false,
    //   };
    //   this.showWizard = true;
    // },

    // openNordVPNOnly() {
    //   this.wizardConfig = {
    //     endOfFlowParam: false,
    //     autoReconfigAvailable: false,
    //     nordVPNWindows: true,
    //   };
    //   this.showWizard = true;
    // },

    // openFinalInstructionsOnly() {
    //   this.wizardConfig = {
    //     endOfFlowParam: true,
    //     autoReconfigAvailable: false,
    //     nordVPNWindows: false,
    //   };
    //   this.showWizard = true;
    // },

    wizardEndHandler() { // Reset vars on wizard completed, closed. Close the window.
      this.showWizard = false;
      this.reconnectIssued = false;
      this.autoReconfigFailed = false;
      this.autoReconfigErrHeader = "";
      this.autoReconfigErrDetails = "";

      sender.CloseVpnWizardWindow(); // this will reset this.$store.state.uiState.vpnWizard.* vars
    },

    onWizardClosed() {
      console.log("Wizard closed");
      this.wizardEndHandler();
    },

    onWizardCompleted(data) {
      console.log("Wizard completed:", data);
      // Handle wizard completion logic here

      // in case of NordVPN on Windows, check whether reconnected already - and, if not, issue reconnect
      if (this.$store.state.uiState.vpnWizard.showNordVpnWindowsStep && this.$store.state.uiState.vpnWizard.issueExplicitConnect && !this.reconnectIssued) {
        sender.Connect();
      }

      this.wizardEndHandler();
    },

    onStepChanged(data) {
      // console.log("Step changed: ", data, "\nautoReconfigFailed=", this.autoReconfigFailed, "\ntimeOfLastPromptToReconfigureOtherVpns=", this.$store.state.uiState.timeOfLastPromptToReconfigureOtherVpns);
      // Handle step change logic here
      sender.SetPermissionReconfigureOtherVPNs(this.toSetVpnCoexistPermission == true);
    },

    async performAutoReconfig() {
      console.log("Performing auto-reconfig...");
      // Add your auto-reconfig logic here

      this.$store.dispatch("uiState/timeOfLastPromptToReconfigureOtherVpns", Date.now()); // store the timestamp only when the user agreed to re-configure other VPNs
      // this.$store.state.uiState.timeOfLastPromptToReconfigureOtherVpns = Date.now();

      if (this.toSetVpnCoexistPermission) {
        sender.SetPermissionReconfigureOtherVPNs(true);
      }

      this.reconnectIssued = true;
      try {
        let resp = await sender.KillSwitchReregister(true); // this will also kick off reconnection attempt
        console.log("KillSwitchReregister resp:\n\n", resp);
        if (resp && resp !== null) {
          if (resp.OtherVpnUnknownToUs != null && resp.OtherVpnUnknownToUs) {
            // TODO: Vlad:
            //  - re-check what "KillSwitchReregister" request returns
            console.log("KillSwitchReregister() returned OtherVpnUnknownToUs");
            sender.SetLogging(true);
            this.autoReconfigFailed = true;
            this.autoReconfigErrHeader = 
              "Error - failed to get top firewall permissions";
            this.autoReconfigErrDetails =
              `Error: ${resp.ErrorMessage}\n\n` +
              `Other VPN \'${resp.OtherVpnName}\' - \'${resp.OtherVpnGUID}\' is not registered in our database, we don't know how to stop it.\n\n` +
              "You can also try the following manual steps to try to allow PL Connect get the necessary top firewall permissions:\n\n" +
              "(1) Disconnect the other VPN and click Fix in PL Connect again. If successful - then reconnect to the other VPN.\n\n" +
              "(2) If previous step failed - stop the Windows service of the other VPN (via Services tab in Task Manager) and click Fix " +
              "in PL Connect again. If successful - then restart the service of the other VPN and reconnect to the other VPN.\n\n" +
              "(3) If previous step failed - uninstall the other VPN and click Fix in PL Connect again. Then reinstall the other VPN and reconnect to it.";
          } else if (resp.ErrorMessage != null && resp.ErrorMessage) {
            console.log("KillSwitchReregister() returned error:\n\n", resp.ErrorMessage);
            sender.SetLogging(true);
            this.autoReconfigFailed = true;
            this.autoReconfigErrHeader = "Error - automatic reconfiguration failed";
            this.autoReconfigErrDetails = resp.ErrorMessage;
          } else if (resp.obj?.ErrorMessage != null && resp.obj?.ErrorMessage) {
            console.log("resp.ErrorMessage:\n\n", resp.obj.ErrorMessage);
          } else
            this.autoReconfigFailed = false;
        }
      } catch (error) {
        console.log("KillSwitchReregister() threw error:\n\n", error);
        sender.SetLogging(true);
        this.autoReconfigFailed = true;
        this.autoReconfigErrHeader = "Error - automatic reconfiguration failed";
        this.autoReconfigErrDetails = error;
      }

      // if (this.$store.state.uiState.vpnWizard.issueExplicitConnect) {
      //   sender.Connect(); // start connection attempt, if explicitly requested
      //   this.reconnectIssued = true;
      // }
    },

    async onSendVpnWizardLogs() {
      try {
        let userComment = this.autoReconfigErrHeader + "\n\n" + this.autoReconfigErrDetails;
        await sender.SubmitRageshakeReport('ui - VPN wizard error', userComment, {});
      } catch (error) {
        console.error('Error submitting VPN wizard logs to Rageshake:', error);
      }
    }
  },
  hasPermissionToReconfigureOtherVPNs: function () {
    return this.$store.state.settings?.daemonSettings?.PermissionReconfigureOtherVPNs ?? false;
  },
};
</script>

<style scoped lang="scss">
@use './scss/vpn-wizard.scss';
</style>
