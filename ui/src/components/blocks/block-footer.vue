<template>

	<!-- Footer with PL Meet link: when logged in -->
	<div 
		v-if="isLoggedIn"
		class="footer_text" style="position: absolute; bottom: 0;"
	>
		For seamless, private, and secure conferencing, open <a :href="openPLMeetWeb"@click="openPLMeetWeb">privateLINE Meet</a>.
	</div>

	<!-- Footer showing when we're using Development REST API servers: when logged out -->
	<div 
		v-if="!isLoggedIn && isDevRestApiBackend"
		class="failed_text" style="position: absolute; bottom: 0;"
	>
		Using <a :href="onSettings"@click="onSettings">Development REST API servers</a>
	</div>

</template>

<script>
const sender = window.ipcSender;

export default {
	data: function () {
    return {
      isDevRestApiBackend: false,
    };
  },
	mounted() {
    this.isDevRestApiBackend = this.isDevRestApiBackendStore;
	},
  watch: {
    isDevRestApiBackendStore() {
      this.isDevRestApiBackend = this.isDevRestApiBackendStore;
    }
  },
	methods: {
    openPLMeetWeb() {
      sender.shellOpenExternal(`https://meet.privateline.network`);
    },
		onSettings() {
      sender.ShowSettings();
    },
  },
	computed: {
    isLoggedIn() {
      //return this.$store.state.vpnState.connectionInfo !== null;
      return this.$store.getters["account/isLoggedIn"];
    },
		isDevRestApiBackendStore() {
      return this.$store.state.usingDevelopmentRestApiBackend;
    },
	},
};
</script>

<!-- Add "scoped" attribute to limit CSS to this component only -->
<style scoped lang="scss">
@import "@/components/scss/constants";

.footer_text {
  padding: 5px 20px 5px 20px;

  color: var(--text-color);
  font-size: 13px;
  line-height: 18px;

  letter-spacing: -0.08px;

	a:link {
  	color: var(--link-color);
	}
}

.failed_text {
  padding: 5px 20px 5px 20px;

  color: var(--text-color);
  font-size: 13px;
  line-height: 18px;

  letter-spacing: -0.08px;

	a:link {
		color: rgb(251, 24, 24);
	  font-weight: bold;
	}
}

</style>
