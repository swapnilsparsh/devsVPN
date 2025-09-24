<template>
  <div class="wizard-overlay" @click.self="closeWizard">
    <div class="wizard-container">
      <!-- Wizard Header -->
      <div class="wizard-header">
        <h2 class="wizard-title">VPN Setup Wizard</h2>
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
        <!-- Auto-reconfig VPN Step -->
        <div v-if="currentStep.id === 'auto-reconfig'" class="wizard-step">
          <div class="step-header">
            <h3>Auto-reconfigure VPN</h3>
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

        <!-- NordVPN Windows Step -->
        <div v-if="currentStep.id === 'nordvpn-windows'" class="wizard-step">
          <div class="step-header">
            <h3>NordVPN on Windows Configuration</h3>
            <p class="step-description">
              Follow these instructions to configure NordVPN settings for
              compatibility with privateLINE.
            </p>
          </div>
          <div class="step-content">
            <slot name="nordvpn-content">
              <!-- Default content for NordVPN step -->
              <div class="info-box">
                <p><strong>Please follow these steps:</strong></p>
                <ol>
                  <li>Open NordVPN application</li>
                  <li>Go to Settings → General</li>
                  <li>Disable "Auto-connect" feature</li>
                  <li>Disconnect from NordVPN if currently connected</li>
                  <li>Close NordVPN application completely</li>
                </ol>
                <p class="warning-text">
                  ⚠️ These changes are necessary to prevent connection
                  conflicts.
                </p>
              </div>
            </slot>
          </div>
        </div>

        <!-- Final Instructions Step -->
        <div v-if="currentStep.id === 'final-instructions'" class="wizard-step">
          <div class="step-header">
            <h3>Setup Complete</h3>
            <p class="step-description">
              Your VPN configuration is now ready. Here are some final
              recommendations.
            </p>
          </div>
          <div class="step-content">
            <slot name="final-instructions-content">
              <!-- Default content for final instructions -->
              <div class="info-box success">
                <p><strong>✓ Configuration completed successfully!</strong></p>
                <p>
                  You can now use privateLINE without conflicts. Here are some
                  tips:
                </p>
                <ul>
                  <li>Use privateLINE as your primary VPN solution</li>
                  <li>
                    If you need to use other VPNs, disconnect from privateLINE
                    first
                  </li>
                  <li>Check your connection status in the main application</li>
                  <li>Contact support if you experience any issues</li>
                </ul>
              </div>
            </slot>
          </div>
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
    // If true, show only the final instructions tab
    endOfFlowParam: {
      type: Boolean,
      default: false,
    },
    // If true, show auto-reconfig VPN step
    autoReconfigAvailable: {
      type: Boolean,
      default: false,
    },
    // If true, show NordVPN on Windows step
    nordVPNWindows: {
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
          id: "auto-reconfig",
          title: "Auto-reconfig VPN",
          condition: () => this.autoReconfigAvailable,
        },
        {
          id: "nordvpn-windows",
          title: "NordVPN Windows",
          condition: () => this.nordVPNWindows,
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
@use "@/components/scss/constants";

.wizard-overlay {
  position: fixed;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  background-color: rgba(0, 0, 0, 0.5);
  display: flex;
  justify-content: center;
  align-items: center;
  z-index: 1000;
}

.wizard-container {
  background: var(--background-color);
  border-radius: 12px;
  width: 90%;
  max-width: 600px;
  max-height: 80vh;
  overflow: hidden;
  box-shadow: 0 10px 25px rgba(0, 0, 0, 0.3);
  display: flex;
  flex-direction: column;
}

.wizard-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 20px 24px;
  border-bottom: 1px solid var(--separator-line-color);
}

.wizard-title {
  margin: 0;
  font-size: 20px;
  font-weight: 600;
  color: var(--text-color);
}

.wizard-close-btn {
  background: none;
  border: none;
  font-size: 24px;
  cursor: pointer;
  color: var(--text-color-details);
  padding: 0;
  width: 32px;
  height: 32px;
  display: flex;
  align-items: center;
  justify-content: center;
  border-radius: 6px;

  &:hover {
    background: var(--background-color-alternate);
  }
}

.wizard-progress {
  padding: 20px 24px;
  border-bottom: 1px solid var(--separator-line-color);
}

.progress-bar {
  width: 100%;
  height: 4px;
  background: var(--background-color-alternate);
  border-radius: 2px;
  overflow: hidden;
  margin-bottom: 16px;
}

.progress-fill {
  height: 100%;
  background: #6f329d;
  border-radius: 2px;
  transition: width 0.3s ease;
}

.step-indicators {
  display: flex;
  justify-content: center;
  gap: 16px;
}

.step-indicator {
  width: 32px;
  height: 32px;
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  font-weight: 600;
  font-size: 14px;
  border: 2px solid var(--separator-line-color);
  background: var(--background-color);
  color: var(--text-color-details);
  transition: all 0.3s ease;

  &.active {
    border-color: #6f329d;
    background: #6f329d;
    color: white;
  }

  &.completed {
    border-color: var(--connection-switch-color);
    background: var(--connection-switch-color);
    color: white;
  }
}

.wizard-content {
  flex: 1;
  overflow-y: auto;
  padding: 24px;
}

.wizard-step {
  height: 100%;
  display: flex;
  flex-direction: column;
}

.step-header {
  margin-bottom: 24px;
}

.step-header h3 {
  margin: 0 0 8px 0;
  font-size: 18px;
  font-weight: 600;
  color: var(--text-color);
}

.step-description {
  margin: 0;
  color: var(--text-color-details);
  font-size: 14px;
  line-height: 1.4;
}

.step-content {
  flex: 1;
}

.info-box {
  background: var(--background-color-alternate);
  border-radius: 8px;
  padding: 20px;
  border-left: 4px solid #6f329d;

  &.success {
    border-left-color: var(--connection-switch-color);
  }

  p {
    margin: 0 0 16px 0;

    &:last-child {
      margin-bottom: 0;
    }
  }

  ul,
  ol {
    margin: 16px 0 0 0;
    padding-left: 20px;

    li {
      margin-bottom: 8px;
      line-height: 1.4;
    }
  }

  .warning-text {
    color: var(--warning-color);
    font-weight: 500;
    margin-top: 16px;
  }
}

.wizard-footer {
  padding: 20px 24px;
  border-top: 1px solid var(--separator-line-color);
  background: var(--background-color);
}

.wizard-actions {
  display: flex;
  align-items: center;
  gap: 12px;
}

.wizard-btn {
  height: 40px;
  min-width: 100px;
  border-radius: 8px;
  font-weight: 600;
  font-size: 14px;
  cursor: pointer;
  transition: all 0.2s ease;

  &:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  &.master {
    background: #6f329d;
    color: white;
    border: none;

    &:hover:not(:disabled) {
      opacity: 0.9;
    }
  }

  &.slave {
    background: var(--button-slave-background);
    color: var(--text-color);
    border: 1px solid var(--separator-line-color);

    &:hover:not(:disabled) {
      background: var(--background-color-alternate);
    }
  }
}

// Scrollbar styling for wizard content
.wizard-content::-webkit-scrollbar {
  width: 6px;
}

.wizard-content::-webkit-scrollbar-track {
  background: var(--background-color-alternate);
  border-radius: 3px;
}

.wizard-content::-webkit-scrollbar-thumb {
  background: var(--separator-line-color);
  border-radius: 3px;

  &:hover {
    background: var(--text-color-details);
  }
}
</style>
