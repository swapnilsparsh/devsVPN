<template>
  <div>
    <div class="settingsTitle">ANTITRACKER SETTINGS</div>

    <div class="defColor" style="margin-bottom: 24px">
      When AntiTracker is enabled, privateLINE blocks ads, malicious websites, and
      third-party trackers using our private DNS servers. Learn more
      about how privateLINE AntiTracker is implemented.
    </div>

    <div class="flexRow paramBlock" style="margin-bottom: 12px">
      <div class="defColor paramName">Block list:</div>
      <select v-model="AtPlusListNameSelected">
        <optgroup
          v-for="group in AtPlusLists"
          :key="group.name"
          :label="group.name"
        >
          <option
            v-for="item in group.lists"
            :key="item.Name"
            :value="item.Name"
          >
            {{ item.Description ? item.Description : item.Name }}
          </option>
        </optgroup>
      </select>
    </div>
    <div class="fwDescription">
      Block lists refer to DNS blocking lists used by our AntiTracker. The
      'Basic', 'Comprehensive', and 'Restrictive' options are combinations of
      individual lists, each offering a different level of protection. You also
      have the freedom to select from individual lists for a more tailored
      AntiTracker experience.
    </div>
    <div class="fwDescription">
      Learn more about AntiTracker block lists.
    </div>

    <div class="param">
      <input
        type="checkbox"
        id="isAntitrackerHardcore"
        v-model="isAntitrackerHardcore"
      />
      <label class="defColor" for="isAntitrackerHardcore">Hardcore Mode</label>
    </div>

    <div class="fwDescription">
      Adding Hardcore mode will block the leading companies with business models
      relying on user surveillance (currently: Google and Facebook).
    </div>
    <div class="fwDescription">
      To better understand how this may impact your experience please refer to
      our.
    </div>
  </div>
</template>

<script>
const sender = window.ipcSender;

import linkCtrl from "@/components/controls/control-link.vue";

export default {
  components: {
    linkCtrl,
  },
  data: function () {
    return {};
  },
  methods: {},
  computed: {
    isAntitrackerHardcore: {
      get() {
        return this.$store.state.settings.antiTracker?.Hardcore;
      },
      async set(value) {
        let at = this.$store.state.settings.antiTracker;
        if (!at)
          at = {
            Enabled: false,
            Hardcore: value,
            AntiTrackerBlockListName: "",
          };
        else at = JSON.parse(JSON.stringify(at));
        at.Hardcore = value;

        this.$store.dispatch("settings/antiTracker", at);
        await sender.SetDNS();
      },
    },
    AtPlusLists: {
      //groups: [
      //  {
      //    name: "Pre-defined lists",
      //    lists: [{"Name":"Basic", "Normal":"", "Hardcore":""}, ...],
      //  },
      //  {
      //    name: "Individual lists",
      //    lists: [{"Name":"Oisdbig", "Normal":"10.0.254.2", "Hardcore":"10.0.254.3"}, ...],
      //  },
      //],
      get() {
        let atPlusSvrs =
          this.$store.state.vpnState.servers.config?.antitracker_plus
            ?.DnsServers;
        if (!atPlusSvrs) {
          return [];
        }

        let listBasic = null;
        let listComprehensive = null;
        let listRestrictive = null;

        let groupPredefined = { name: "Pre-defined lists", lists: [] };
        let groupIndividual = { name: "Individual lists", lists: [] };

        for (var s of atPlusSvrs) {
          switch (s.Name) {
            case "Basic":
              listBasic = s;
              break;
            case "Comprehensive":
              listComprehensive = s;
              break;
            case "Restrictive":
              listRestrictive = s;
              break;
            default:
              groupIndividual.lists.push(s);
              break;
          }
        }
        if (listBasic) groupPredefined.lists.push(listBasic);
        if (listComprehensive) groupPredefined.lists.push(listComprehensive);
        if (listRestrictive) groupPredefined.lists.push(listRestrictive);

        return [groupPredefined, groupIndividual];
      },
    },
    AtPlusListNameSelected: {
      get() {
        return this.$store.state.settings.antiTracker.AntiTrackerBlockListName;
      },
      set(value) {
        let at = this.$store.state.settings.antiTracker;
        if (!at)
          at = {
            Enabled: false,
            Hardcore: false,
            AntiTrackerBlockListName: value,
          };
        else at = JSON.parse(JSON.stringify(at));
        at.AntiTrackerBlockListName = value;

        this.$store.dispatch("settings/antiTracker", at);
        sender.SetDNS();
      },
    },
  },
};
</script>

<style scoped lang="scss">
@use "@/components/scss/constants";

.defColor {
  @extend .settingsDefaultTextColor;
}

div.fwDescription {
  @extend .settingsGrayLongDescriptionFont;
  margin-top: 9px;
  margin-bottom: 17px;
  margin-left: 22px;
  max-width: 425px;
}

div.param {
  @extend .flexRow;
  margin-top: 3px;
}

button.link {
  @extend .noBordersTextBtn;
  @extend .settingsLinkText;
  font-size: inherit;
}
label {
  margin-left: 1px;
  font-weight: 500;
}

div.paramName {
  min-width: 100px;
  max-width: 100px;
}
</style>
