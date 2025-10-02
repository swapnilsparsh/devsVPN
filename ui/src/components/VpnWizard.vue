<template>
  <div class="wizard-overlay" @click.self="closeWizard">
    <div class="wizard-container">
      <!-- Wizard Header -->
      <div class="wizard-header">
        <h2 class="wizard-title">Troubleshoot privateLINE Connectivity</h2>
        <button class="wizard-close-btn" @click="closeWizard">
          <span>&times;</span>
        </button>
      </div>

      <!-- Progress Indicator -->
      <div class="wizard-progress" v-if="!endOfFlowParam">
        <div class="progress-bar">
          <div
            class="progress-fill"
            :style="{ width: progressPercentage + '%' }"
          ></div>
        </div>
        <div class="step-indicators">
          <div
            v-for="(step, index) in availableSteps"
            :key="step.id"
            class="step-indicator"
            :class="{
              active: index === currentStepIndex,
              completed: index < currentStepIndex,
            }"
          >
            {{ index + 1 }}
          </div>
        </div>
      </div>

      <!-- Wizard Content -->
      <div class="wizard-content">
        <!-- Introductory Screen Step -->
        <div v-if="currentStep.id === 'intro-screen'" class="wizard-step">
          <div class="step-header">
            <h3>{{this.$store.state.uiState.vpnWizard.introHeader}}</h3>
            <p class="step-description">
              {{this.$store.state.uiState.vpnWizard.introDescr}}
            </p>
          </div>
          <div v-if="this.otherVpnsDetected" class="step-content">
            <slot name="intro-screen-content">
              <div class="info-box">
                <p><strong>Other VPNs detected, that may be blocking privateLINE connectivity</strong></p>
                  <ul>
                    <li v-for="otherVpnName in this.$store.state.vpnState.firewallState.ReconfigurableOtherVpnsNames">
                      {{ otherVpnName }}
                    </li>
                  </ul>
              </div>
            </slot>
          </div>
        </div>
        
        <!-- NordVPN Windows Step -->
        <div v-if="currentStep.id === 'nordvpn-windows'" class="wizard-step">
          <div class="step-header">
            <h3>NordVPN detected</h3>
            <p class="step-description">
              Please follow these instructions to configure NordVPN for
              compatibility with privateLINE:
            </p>
          </div>
          <div class="step-content">
            <slot name="nordvpn-content">
              <div class="info-box">
                <!-- <p><strong>Please configure NordVPN as follows:</strong></p> -->
                <ol class="no-top-margin">
                  <li>Open NordVPN Settings</li>
                  <li>Under Settings / Connection:</li>
                    <ul><li>Stay invisible on LAN = Off</li></ul>
                  <li>Under Settings / Killswitch:</li>
                    <ul><li>Internet Kill Switch = Off</li></ul>
                  <li>Under Settings / Split tunnelling:</li>
                    <ul><li>Split tunnelling = On</li></ul>
                    <ul><li>Add apps / Browse apps:</li>
                      <ul><!-- TODO: Vlad - get actual binary paths from daemon, instead of hardcoding -->
                        <li class="monospace-text">c:\Program Files\privateLINE Connect\privateline-connect-svc.exe</li>
                        <li class="monospace-text">c:\Program Files\privateLINE Connect\ui\privateline-connect-ui.exe</li>
                        <li class="monospace-text">c:\Program Files\privateLINE Connect\WireGuard\x86_64\wg.exe</li>
                        <li class="monospace-text">c:\Program Files\privateLINE Connect\WireGuard\x86_64\wireguard.exe</li>
                      </ul>
                    </ul>
                </ol>
              </div>
            </slot>
            <p class="warning-text">
              ⚠️ It is necessary to configure NordVPN this way to ensure privateLINE connectivity.
            </p>
          </div>
       </div>

        <!-- Auto-reconfig VPN Step -->
        <div v-if="currentStep.id === 'auto-reconfig'" class="wizard-step">
          <div class="step-header">
            <h3>Auto-Reconfigure Other VPNs</h3>
            <p class="step-description">
              Allow privateLINE to automatically reconfigure other VPN
              applications to prevent conflicts.
            </p>
          </div>
          <div class="step-content">
            <slot name="auto-reconfig-content">
              <!-- Default content for auto-reconfig step -->
              <div class="info-box">
                <p>
                  This step will help configure your system to work seamlessly
                  with privateLINE by adjusting settings of other VPN
                  applications.
                </p>
                <ul>
                  <li>Detect conflicting VPN configurations</li>
                  <li>Temporarily adjust network settings</li>
                  <li>Ensure optimal privateLINE performance</li>
                </ul>
              </div>
            </slot>
          </div>
        </div>

        <!-- Final Instructions Step -->
        <div v-if="currentStep.id === 'final-instructions'" class="wizard-step">
          <slot name="final-instructions-content">
            <div class="step-header">
              <h3>Troubleshooting Complete</h3>
              <p class="step-description">
                Your VPN configuration is now ready. Here are some final
                recommendations.
              </p>
            </div>
            <div class="step-content">
                <!-- Default content for final instructions -->
                <div class="info-box success">
                  <p><strong>✓ Re-configuration completed successfully!</strong></p>
                  <p>
                    You should now be able to use privateLINE without conflicts. Here are some
                    tips:
                  </p>
                  <ul>
                    <li>Check your connection status in the main application</li>
                    <li>If you need to use other VPNs, disable Total Shield in privateLINE first </li>
                    <li>Contact support if you experience any issues</li>
                  </ul>
                </div>
            </div>
          </slot>
        </div>
      </div>

      <!-- Wizard Footer -->
      <div class="wizard-footer">
        <div class="wizard-actions">
          <button
            v-if="!isFirstStep && !endOfFlowParam"
            class="slave wizard-btn"
            @click="previousStep"
            :disabled="isProcessing"
          >
            Back
          </button>

          <div style="flex-grow: 1"></div>

          <button
            v-if="!isLastStep"
            class="master wizard-btn"
            @click="nextStep"
            :disabled="isProcessing"
          >
            {{ endOfFlowParam ? "Close" : "Next" }}
          </button>

          <button
            v-if="isLastStep"
            class="master wizard-btn"
            @click="completeWizard"
            :disabled="isProcessing"
          >
            Complete
          </button>
        </div>
      </div>
    </div>
  </div>
</template>

<script>
export default {
  name: "VpnWizard",
  props: {
    // Custom message to show on intro screen
    introDescr: {
      type: String,
      default: "",
    },
    // If true, show only the final instructions tab
    endOfFlowParam: {
      type: Boolean,
      default: false,
    },
    // If true, show NordVPN on Windows step
    nordVPNWindows: {
      type: Boolean,
      default: false,
    },
    // If true, show auto-reconfig VPN step
    autoReconfigAvailable: {
      type: Boolean,
      default: false,
    },
  },
  data() {
    return {
      currentStepIndex: 0,
      isProcessing: false,
      allSteps: [
        {
          id: "intro-screen",
          title: "Introductory screen",
          condition: () => true, // Always show
        },
        {
          id: "nordvpn-windows",
          title: "NordVPN Windows",
          // condition: () => this.nordVPNWindows,
          condition: () => this.$store.state.uiState.vpnWizard.showNordVpnWindowsStep,
        },
        {
          id: "auto-reconfig",
          title: "Auto-reconfig VPN",
          // condition: () => this.autoReconfigAvailable,
          condition: () => this.$store.state.uiState.vpnWizard.showAutoReconfigVpnStep,
        },
        {
          id: "final-instructions",
          title: "Final Instructions",
          condition: () => true, // Always show
        },
      ],
    };
  },
  computed: {
    availableSteps() {
      if (this.endOfFlowParam) {
        // Only show final instructions step
        return this.allSteps.filter((step) => step.id === "final-instructions");
      }
      return this.allSteps.filter((step) => step.condition());
    },
    currentStep() {
      return (
        this.availableSteps[this.currentStepIndex] || this.availableSteps[0]
      );
    },
    isFirstStep() {
      return this.currentStepIndex === 0;
    },
    isLastStep() {
      return this.currentStepIndex === this.availableSteps.length - 1;
    },
    progressPercentage() {
      if (this.availableSteps.length === 0) return 100;
      return ((this.currentStepIndex + 1) / this.availableSteps.length) * 100;
    },
    otherVpnsDetected() {
      return this.$store.state.vpnState?.firewallState?.ReconfigurableOtherVpnsDetected;
    },
  },
  mounted() {
    // Focus management for accessibility
    this.$nextTick(() => {
      const firstFocusable = this.$el.querySelector(
        'button, [tabindex]:not([tabindex="-1"])'
      );
      if (firstFocusable) {
        firstFocusable.focus();
      }
    });
  },
  methods: {
    nextStep() {
      if (this.isLastStep) {
        this.completeWizard();
        return;
      }

      if (this.currentStepIndex < this.availableSteps.length - 1) {
        this.currentStepIndex++;
        this.$emit("step-changed", {
          stepId: this.currentStep.id,
          stepIndex: this.currentStepIndex,
        });
      }
    },
    previousStep() {
      if (this.currentStepIndex > 0) {
        this.currentStepIndex--;
        this.$emit("step-changed", {
          stepId: this.currentStep.id,
          stepIndex: this.currentStepIndex,
        });
      }
    },
    completeWizard() {
      this.$emit("wizard-completed", {
        completedSteps: this.availableSteps.map((step) => step.id),
      });
      this.closeWizard();
    },
    closeWizard() {
      this.$emit("wizard-closed");
    },
    // Method to programmatically go to a specific step
    goToStep(stepId) {
      const stepIndex = this.availableSteps.findIndex(
        (step) => step.id === stepId
      );
      if (stepIndex !== -1) {
        this.currentStepIndex = stepIndex;
        this.$emit("step-changed", {
          stepId: this.currentStep.id,
          stepIndex: this.currentStepIndex,
        });
      }
    },
  },
};
</script>

<style scoped lang="scss">
@use './scss/vpn-wizard.scss';
</style>
