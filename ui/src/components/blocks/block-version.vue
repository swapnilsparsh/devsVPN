<template>
<!-- VERSION -->
	<div
		style="flex-grow: 1; text-align: center; cursor: pointer"
		v-on:click="onVersionClick()"
	>
		<div v-if="versionSingle" class="version">
			<!-- single version -->
			{{ versionSingle }}
		</div>

		<div v-else>
			<!-- daemon and UI versions different-->
			<div class="version">
				{{ versionUI }}
			</div>
			<div class="version">daemon {{ versionDaemon }}</div>
		</div>
	</div>
</template>

<script>
const sender = window.ipcSender;

export default {
	computed: {
    versionSingle: function () {
      if (this.versionDaemon === this.versionUI) return this.versionDaemon;
      return null;
    },
    versionDaemon: function () {
      try {
        let v = this.$store.state.daemonVersion;
        if (!v) return "version unknown";
        return `v${v}`;
      } catch (e) {
        return "version unknown";
      }
    },
    versionUI: function () {
      try {
        let v = sender.appGetVersion().Version;
        if (!v) return "version unknown";
        return `v${v}`;
      } catch (e) {
        return "version unknown";
      }
    },
  },

  methods: {
    onVersionClick: function () {
      let infoStr = "";

      infoStr += "Daemon: ";
      if (!this.versionDaemon) infoStr += "version unknown";
      else infoStr += this.versionDaemon;
      if (this.$store.state.daemonProcessorArch)
        infoStr += ` [${this.$store.state.daemonProcessorArch}]`;
      infoStr += "\n";

      const uiVer = sender.appGetVersion();
      infoStr += "UI: ";
      if (!uiVer || !uiVer.Version) infoStr += "version unknown";
      else infoStr += uiVer.Version;
      if (uiVer && uiVer.ProcessorArch) infoStr += ` [${uiVer.ProcessorArch}]`;
      infoStr += "\n";

      infoStr += "\n" + navigator.userAgent;

      sender.showMessageBoxSync({
        type: "info",
        buttons: ["OK"],
        message: "privateLINE version info",
        detail: infoStr,
      });
    },
  },
};
</script>

<!-- Add "scoped" attribute to limit CSS to this component only -->
<style scoped lang="scss">
@import "@/components/scss/constants";

div.version {
  color: gray;
}

</style>
