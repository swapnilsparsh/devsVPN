<template>
	<!-- Footer with PL Meet link -->
	<div 
		v-if="this.$store.state.vpnState.connectionInfo !== null"
		class="footer_text" style="position: absolute; bottom: 0;"
	>
		For seamless, private, and secure conferencing, open <a :href="openPLMeetWeb"@click="openPLMeetWeb">privateLINE Meet</a>.
	</div>
</template>

<script>
const sender = window.ipcSender;

export default {
  methods: {
    openPLMeetWeb() {
      sender.shellOpenExternal(`https://meet.privateline.network`);
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
  	color: #0000ff;
	}
}

</style>
