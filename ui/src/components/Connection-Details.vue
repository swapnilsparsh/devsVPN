<template>
    <div>
        <!-- Wireguard -->
        <div v-show="true" class="connectionDetailWrap">
            <div v-if="true">
                <!-- <div class="settingsBoldFont">Wireguard key information:</div> -->
                <div style="height: 16px;"></div>
                <!-- <spinner :loading="isProcessing" /> -->
                <div class="flexRow paramBlockDetailedConfig">
                    <div class="defColor paramName">Protocol:</div>
                    <div class="detailedParamValue">
                        {{ 'Wireguard' }}
                    </div>
                </div>
                <div class="flexRow paramBlockDetailedConfig">
                    <div class="defColor paramName">Local IP Address:</div>
                    <div class="detailedParamValue">
                        {{ this.$store.state.account.session.WgLocalIP }}
                    </div>
                </div>
                <!-- <div class="flexRow paramBlockDetailedConfig">
                    <div class="defColor paramName">Port:</div>
                    <div class="detailedParamValue">
                        {{ 'Port' }}
                    </div>
                </div> -->
                <div class="flexRow paramBlockDetailedConfig">
                    <div class="defColor paramName">Public key:</div>
                    <div class="detailedParamValue">
                        {{ this.$store.state.account.session.WgPublicKey }}
                    </div>
                </div>
                <div class="flexRow paramBlockDetailedConfig">
                    <div class="defColor paramName">Generated:</div>
                    <div class="detailedParamValue">
                        {{ wgKeysGeneratedDateStr }}
                    </div>
                </div>
                <!-- <div class="flexRow paramBlockDetailedConfig">
                    <div class="defColor paramName">Scheduled rotation date:</div>
                    <div class="detailedParamValue">
                        {{ wgKeysWillBeRegeneratedStr }}
                    </div>
                </div> -->
                <div class="flexRow paramBlockDetailedConfig">
                    <div class="defColor paramName">Expiration date:</div>
                    <div class="detailedParamValue">
                        {{ wgKeysExpirationDateStr }}
                    </div>
                </div>
                <!-- <div class="flexRow paramBlockDetailedConfig">
                    <div class="defColor paramName">Quantum Resistance:</div>
                    <div class="detailedParamValue">
                        {{ wgQuantumResistanceStr }}
                    </div>
                    <button class="noBordersBtn flexRow" title="Info"
                        v-on:click="this.$refs.infoWgQuantumResistance.showModal()">
                        <img src="@/assets/question.svg" />
                    </button>
                </div> -->
                <ComponentDialog ref="infoWgQuantumResistance" header="Info">
                    <div>
                        <p>
                            Quantum Resistance: Indicates whether your current WireGuard VPN
                            connection is using additional protection measures against
                            potential future quantum computer attacks.
                        </p>
                        <p>
                            When Enabled, a Pre-shared key has been securely exchanged between
                            your device and the server using post-quantum Key Encapsulation
                            Mechanism (KEM) algorithms. If Disabled, the current VPN
                            connection, while secure under today's standards, does not include
                            this extra layer of quantum resistance.
                        </p>
                    </div>
                </ComponentDialog>
            </div>
        </div>

    </div>
</template>

<script>

import { dateDefaultFormat } from "@/helpers/helpers";

import ComponentDialog from "@/components/component-dialog.vue";

const sender = window.ipcSender;

export default {
    components: { ComponentDialog },
    data: function () {
        return {
            isPortModified: false,
            isProcessing: false,
            openvpnManualConfig: false,
        };
    },
    mounted() {
    },
    watch: {
        // If port was changed in conneted state - reconnect
        async port(newValue, oldValue) {
            if (this.isPortModified === false) return;
            if (newValue == null || oldValue == null) return;
            if (newValue.port === oldValue.port && newValue.type === oldValue.type)
                return;
            await this.reconnect();
        },
    },

    methods: {
        onWgKeyRegenerate: async function () {
            try {
                this.isProcessing = true;
                await sender.WgRegenerateKeys();
            } catch (e) {
                console.log(`ERROR: ${e}`);
                sender.showMessageBoxSync({
                    type: "error",
                    buttons: ["OK"],
                    message: "Error generating WireGuard keys",
                    detail: e,
                });
            } finally {
                this.isProcessing = false;
            }
        },
        getWgKeysGenerated: function () {
            if (
                this.$store.state.account == null ||
                this.$store.state.account.session == null ||
                this.$store.state.account.session.WgKeyGenerated == null
            )
                return null;
            return new Date(this.$store.state.account.session.WgKeyGenerated);
        },
        formatDate: function (d) {
            if (d == null) return null;
            return dateDefaultFormat(d);
        },
    },
    computed: {
        IsAccountActive: function () {
            // if no info about account status - let's believe that account is active
            if (
                !this.$store.state.account ||
                !this.$store.state.account.accountStatus
            )
                return true;
            return this.$store.state.account?.accountStatus?.Active === true;
        },
        wgKeyRegenerationInterval: {
            get() {
                return this.$store.state.account.session.WgKeysRegenIntervalSec;
            },
            set(value) {
                // daemon will send back a Hello response with updated 'session.WgKeysRegenIntervalSec'
                sender.WgSetKeysRotationInterval(value);
            },
        },

        wgKeysGeneratedDateStr: function () {
            return this.formatDate(this.getWgKeysGenerated());
        },
        wgKeysWillBeRegeneratedStr: function () {
            let t = this.getWgKeysGenerated();
            if (t == null) return null;

            t.setSeconds(
                t.getSeconds() +
                this.$store.state.account.session.WgKeysRegenIntervalSec,
            );

            let now = new Date();
            if (t < now) {
                // Do not show planned regeneration date in the past (it can happen after the computer wake up from a long sleep)
                // Show 'today' as planned date to regenerate keys in this case.
                // (the max interval to check if regeneration required is defined on daemon side, it is less than 24 hours)
                t = now;
            }

            return this.formatDate(t);
        },
        wgKeysExpirationDateStr: function () {
            let t = this.getWgKeysGenerated();
            if (t == null) return null;
            t.setSeconds(t.getSeconds() + 40 * 24 * 60 * 60); // 40 days
            return this.formatDate(t);
        },
        wgRegenerationIntervals: function () {
            let ret = [{ text: "1 day", seconds: 24 * 60 * 60 }];
            for (let i = 2; i <= 30; i++) {
                ret.push({ text: `${i} days`, seconds: i * 24 * 60 * 60 });
            }
            return ret;
        },
        wgQuantumResistanceStr: function () {
            if (this.$store.state.account.session.WgUsePresharedKey === true)
                return "Enabled";
            return "Disabled";
        },
    },
};
</script>

<style scoped lang="scss">
@import "@/components/scss/constants";
@import "@/components/scss/platform/base";

.connectionDetailWrap {
    padding: 5px 20px 5px 20px;

}

div.detailedConfigParamBlock {
    @extend .flexRow;
    margin-top: 10px;
    width: 100%;
}

div.detailedParamValue {
    opacity: 0.7;

    overflow-wrap: break-word;
    -webkit-user-select: text;
    user-select: text;
    letter-spacing: 0.1px;
    overflow-wrap: anywhere;
    font-size: 11px;
    padding: 2px 0px 2px 0px;
}

div.paramName {
    min-width: 120px;
    max-width:120px;
    font-size: 11px
}
</style>