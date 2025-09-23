<template>
  <div class="example-container">
    <h2>VPN Wizard Usage Examples</h2>

    <!-- Example buttons to trigger different wizard configurations -->
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

    <!-- VPN Wizard Component -->
    <VpnWizard
      v-if="showWizard"
      :endOfFlowParam="wizardConfig.endOfFlowParam"
      :autoReconfigAvailable="wizardConfig.autoReconfigAvailable"
      :nordVPNWindows="wizardConfig.nordVPNWindows"
      @wizard-closed="onWizardClosed"
      @wizard-completed="onWizardCompleted"
      @step-changed="onStepChanged"
    >
      <!-- Custom content slots (optional) -->
      <template #auto-reconfig-content>
        <div class="custom-content">
          <h4>Custom Auto-reconfig Content</h4>
          <p>
            This is custom content for the auto-reconfig step. You can put any
            Vue template content here.
          </p>
          <div class="action-buttons">
            <button class="master small-btn" @click="performAutoReconfig">
              Start Auto-reconfig
            </button>
          </div>
        </div>
      </template>

      <template #nordvpn-content>
        <div class="custom-content">
          <h4>Custom NordVPN Instructions</h4>
          <p>These are customized instructions for NordVPN configuration.</p>
          <div class="instruction-steps">
            <div
              class="step-item"
              v-for="(step, index) in nordvpnSteps"
              :key="index"
            >
              <span class="step-number">{{ index + 1 }}</span>
              <span class="step-text">{{ step }}</span>
            </div>
          </div>
        </div>
      </template>

      <template #final-instructions-content>
        <div class="custom-content">
          <h4>Custom Final Instructions</h4>
          <p>Your custom completion message and next steps.</p>
          <ul>
            <li>Custom instruction 1</li>
            <li>Custom instruction 2</li>
            <li>Custom instruction 3</li>
          </ul>
        </div>
      </template>
    </VpnWizard>
  </div>
</template>

<script>
import VpnWizard from "./VpnWizard.vue";

export default {
  name: "VpnWizardExample",
  components: {
    VpnWizard,
  },
  data() {
    return {
      showWizard: false,
      wizardConfig: {
        endOfFlowParam: false,
        autoReconfigAvailable: false,
        nordVPNWindows: false,
      },
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
    openFullWizard() {
      this.wizardConfig = {
        endOfFlowParam: false,
        autoReconfigAvailable: true,
        nordVPNWindows: true,
      };
      this.showWizard = true;
    },

    openAutoReconfigOnly() {
      this.wizardConfig = {
        endOfFlowParam: false,
        autoReconfigAvailable: true,
        nordVPNWindows: false,
      };
      this.showWizard = true;
    },

    openNordVPNOnly() {
      this.wizardConfig = {
        endOfFlowParam: false,
        autoReconfigAvailable: false,
        nordVPNWindows: true,
      };
      this.showWizard = true;
    },

    openFinalInstructionsOnly() {
      this.wizardConfig = {
        endOfFlowParam: true,
        autoReconfigAvailable: false,
        nordVPNWindows: false,
      };
      this.showWizard = true;
    },

    onWizardClosed() {
      console.log("Wizard closed");
      this.showWizard = false;
    },

    onWizardCompleted(data) {
      console.log("Wizard completed:", data);
      this.showWizard = false;
      // Handle wizard completion logic here
    },

    onStepChanged(data) {
      console.log("Step changed:", data);
      // Handle step change logic here
    },

    performAutoReconfig() {
      console.log("Performing auto-reconfig...");
      // Add your auto-reconfig logic here
    },
  },
};
</script>

<style scoped lang="scss">
@use "@/components/scss/constants";

.example-container {
  padding: 20px;
}

.example-buttons {
  display: flex;
  gap: 12px;
  flex-wrap: wrap;
  margin-bottom: 20px;
}

.example-btn {
  height: 40px;
  min-width: 140px;
  border-radius: 8px;
  font-weight: 600;
  font-size: 14px;
  cursor: pointer;

  &.master {
    background: #6f329d;
    color: white;
    border: none;

    &:hover {
      opacity: 0.9;
    }
  }

  &.slave {
    background: var(--button-slave-background);
    color: var(--text-color);
    border: 1px solid var(--separator-line-color);

    &:hover {
      background: var(--background-color-alternate);
    }
  }
}

.custom-content {
  h4 {
    margin: 0 0 12px 0;
    color: var(--text-color);
    font-size: 16px;
  }

  p {
    margin: 0 0 16px 0;
    color: var(--text-color-details);
    line-height: 1.5;
  }
}

.action-buttons {
  margin-top: 20px;
}

.small-btn {
  height: 32px;
  padding: 0 16px;
  border-radius: 6px;
  font-weight: 600;
  font-size: 12px;
  cursor: pointer;
  border: none;

  &.master {
    background: #6f329d;
    color: white;

    &:hover {
      opacity: 0.9;
    }
  }
}

.instruction-steps {
  margin-top: 16px;
}

.step-item {
  display: flex;
  align-items: flex-start;
  margin-bottom: 12px;

  .step-number {
    background: #6f329d;
    color: white;
    width: 24px;
    height: 24px;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 12px;
    font-weight: 600;
    margin-right: 12px;
    flex-shrink: 0;
  }

  .step-text {
    color: var(--text-color);
    line-height: 1.5;
  }
}
</style>
