<template>
  <div class="defaultMainDiv">
    <div class="settingsBoldFont" style="margin-top: 0px; margin-bottom: 12px">
      Please enter a password to enable EAA:
    </div>
    <div class="flexRow">
      <div class="settingsDefaultTextColor paramName">Password:</div>
      <input
        ref="passwordField"
        type="password"
        style="flex-grow: 1"
        class="settingsTextInput minSize"
        placeholder=""
        v-model="newPass"
        v-on:keyup.enter="onApplyNewPassword()"
      />
    </div>
    <div class="flexRow">
      <div class="settingsDefaultTextColor paramName">Confirm password:</div>
      <input
        type="password"
        style="flex-grow: 1"
        class="settingsTextInput minSize"
        placeholder=""
        v-model="newPassConfirm"
        v-on:keyup.enter="onApplyNewPassword()"
      />
    </div>

    <div class="flexRow" style="margin-top: 10px">
      <div style="flex-grow: 1"></div>
      <div class="flexRow">
        <button
          class="slave"
          style="height: 28px; min-width: 100px"
          v-on:click="onCancel()"
        >
          Cancel
        </button>
        <button
          class="master"
          style="height: 28px; min-width: 100px; margin-left: 12px"
          v-on:click="onApplyNewPassword()"
        >
          Enable
        </button>
      </div>
    </div>
  </div>
</template>

<script>
const sender = window.ipcSender;

export default {
  props: {
    onClose: Function,
  },

  mounted() {
    if (this.$refs.passwordField) this.$refs.passwordField.focus();
  },
  data: function () {
    return {
      newPass: "",
      newPassConfirm: "",
    };
  },

  computed: {
    IsPmEnabled: function () {
      return this.$store.state.paranoidModeStatus.IsEnabled;
    },
  },

  methods: {
    close() {
      if (this.onClose) this.onClose();
    },
    onCancel() {
      this.close();
    },
    async onApplyNewPassword() {
      if (!this.newPass) {
        await sender.showMessageBoxSync({
          type: "warning",
          buttons: ["OK"],
          message: "Enhanced App Authentication",
          detail: `Please, enter password`,
        });
        return;
      }
      if (this.newPass != this.newPassConfirm) {
        await sender.showMessageBoxSync({
          type: "warning",
          buttons: ["OK"],
          message: "Enhanced App Authentication",
          detail: `The passwords entered do not match. Please try again.`,
        });
        return;
      }

      if (this.newPass != this.newPass.trim()) {
        await sender.showMessageBoxSync({
          type: "warning",
          buttons: ["OK"],
          message: "Enhanced App Authentication",
          detail: `Bad password. Please, avoid using space symbols`,
        });
        return;
      }

      try {
        await sender.setParanoidModePassword(this.newPass);
        this.close();
      } catch (e) {
        console.error(e);
        sender.showMessageBoxSync({
          type: "error",
          buttons: ["OK"],
          message: `Failed to enable EAA`,
          detail: e,
        });
      }
    },
  },
};
</script>

<style scoped lang="scss">
@use "@/components/scss/constants";

div.paramName {
  min-width: 120px;
  max-width: 120px;
}

input.minSize {
  min-width: 260px;
}
</style>
