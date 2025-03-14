<template>
  <div class="flexColumn" style="justify-content: space-between; width: 100%">
    <div class="flexColumn">
      <div class="flexRow">
        <div class="settingsTitle">Manage Device</div>
      </div>

      <!-- =================== Manage device start =================== -->
      <div class="device-limit-container">
        <!-- Search Input -->
        <div class="search-container">
          <input type="text" v-model="searchQuery" placeholder="Search" class="search-input" />
        </div>

        <!-- Table -->
        <div class="device-list">
          <table>
            <thead>
              <tr>
                <th style="width: 30px;">Sr. No.</th>
                <th>Action</th>
                <th class="device-name">Device Name</th>
                <th>Device ID</th>
                <th>Platform</th>
                <th>Allocated IP</th>
                <th>Tunnel Status</th>
                <th>Device Status</th>
                <th>Configured On</th>
                <th>Handshake</th>
                <th>Received Data</th>
                <th class="device-name">Transformed Data</th>
                <!-- <th>Action</th> -->
              </tr>
            </thead>
            <tbody>
              <tr v-for="(device, index) in paginatedData" :key="device.device_id">
                <td style="width: 30px;">{{ index + 1 + (currentPage - 1) * itemsPerPage }}</td>
                <td>
                  <span class="icon delete-icon" style="margin-right: 15px;">
                    <img style="vertical-align: middle" src="@/assets/eye-open.svg" />
                  </span>
                  <span class="icon view-icon" style="display: inline-block; ">
                    <img style="vertical-align: middle" src="@/assets/delete.png" height="17" width="17" />
                  </span>
                </td>
                <td class="device-name">{{ device.device_name }}</td>
                <td>{{ device.device_id }}</td>
                <td>{{ device.platform }}</td>
                <td>{{ device.allocated_ip }}</td>
                <td><span class="status-shield">Shield</span></td>
                <td class="device-name">{{ device.device_status || '-' }}</td>
                <td class="device-name">{{ formatDate(device.configured_on) }}</td>
                <td class="device-name">{{ device.handshake }}</td>
                <td class="device-name">{{ device.received_data }}</td>
                <td class="device-name">{{ device.transformed_data }}</td>
                <!-- <td>
                  <span class="icon delete-icon" style="margin-right: 5px;">
                    <img style="vertical-align: middle" src="@/assets/eye-open.svg" />
                  </span>
                  <span class="icon view-icon" style="display: inline-block; ">
                    <img style="vertical-align: middle" src="@/assets/delete.png" height="17" width="17" />
                  </span>
                </td> -->
              </tr>
            </tbody>
          </table>
        </div>

        <!-- Pagination Controls -->
        <div class="pagination">
          <button @click="changePage(1)" :disabled="currentPage === 1">«</button>

          <button v-if="currentPage > 2" @click="changePage(currentPage - 1)">{{ currentPage - 1 }}</button>

          <button class="active">{{ currentPage }}</button>

          <button v-if="currentPage < totalPages - 1" @click="changePage(currentPage + 1)">{{ currentPage + 1
          }}</button>

          <span v-if="currentPage < totalPages - 2">...</span>

          <button v-if="currentPage < totalPages" @click="changePage(totalPages)">{{ totalPages }}</button>

          <button @click="changePage(currentPage + 1)" :disabled="currentPage >= totalPages">»</button>
        </div>
      </div>
      <!-- =================== Manage device end =================== -->

    </div>

  </div>
</template>

<script>
import { dateDefaultFormat } from "@/helpers/helpers";
import {
  getDateInShortMonthFormat,
  getDaysDifference,
} from "../../helpers/renderer";
import ShimmerEffect from "../Shimmer";

import qrcode from "qrcode-generator";

const sender = window.ipcSender;

export default {
  components: {
    ShimmerEffect,
  },
  data: function () {
    return {
      apiProfileTimeout: null,
      apiDeviceListTimeout: null,
      apiSubscriptionTimeout: null,
      isProcessing: true,
      isSubscriptionProcessing: true,
      accountShimmerItems: Array(4).fill(null),
      isAccountIDBlurred: true,
      acctIdQRCodeSvg: "",

      // Custom Table 
      searchQuery: "",
      currentPage: 1,
      itemsPerPage: 10,
      deviceListData: [
        { device_name: "PL Connect - 9be4ae22", device_id: "2781a0a5ed652eb6926f", platform: "Linux", allocated_ip: "172.16.0.10/32", tunnel_status: "Shield", device_status: "-", configured_on: "2025-03-12", handshake: "7h:35m:38s", received_data: "632KB", transformed_data: "7MB" },
        { device_name: "PL Connect - d2b17ec8", device_id: "3b2934ab137b36f59f9c", platform: "Windows", allocated_ip: "172.16.0.107/32", tunnel_status: "Shield", device_status: "-", configured_on: "2025-03-11", handshake: "8h:44m", received_data: "31MB", transformed_data: "153MB" },
        { device_name: "PL Connect - ffb09758", device_id: "96734c190dad42b4422", platform: "Windows", allocated_ip: "172.16.0.53/32", tunnel_status: "Shield", device_status: "-", configured_on: "2025-02-22", handshake: "9h:28m:13s", received_data: "568MB", transformed_data: "4GB" },
        { device_name: "PL Connect - ffb09758", device_id: "96734c190dad42b4422", platform: "Windows", allocated_ip: "172.16.0.53/32", tunnel_status: "Shield", device_status: "-", configured_on: "2025-02-22", handshake: "9h:28m:13s", received_data: "568MB", transformed_data: "4GB" },
        { device_name: "PL Connect - ffb09758", device_id: "96734c190dad42b4422", platform: "Windows", allocated_ip: "172.16.0.53/32", tunnel_status: "Shield", device_status: "-", configured_on: "2025-02-22", handshake: "9h:28m:13s", received_data: "568MB", transformed_data: "4GB" },
        { device_name: "PL Connect - ffb09758", device_id: "96734c190dad42b4422", platform: "Windows", allocated_ip: "172.16.0.53/32", tunnel_status: "Shield", device_status: "-", configured_on: "2025-02-22", handshake: "9h:28m:13s", received_data: "568MB", transformed_data: "4GB" },
        { device_name: "PL Connect - ffb09758", device_id: "96734c190dad42b4422", platform: "Windows", allocated_ip: "172.16.0.53/32", tunnel_status: "Shield", device_status: "-", configured_on: "2025-02-22", handshake: "9h:28m:13s", received_data: "568MB", transformed_data: "4GB" },
        { device_name: "PL Connect - ffb09758", device_id: "96734c190dad42b4422", platform: "Windows", allocated_ip: "172.16.0.53/32", tunnel_status: "Shield", device_status: "-", configured_on: "2025-02-22", handshake: "9h:28m:13s", received_data: "568MB", transformed_data: "4GB" },
        { device_name: "PL Connect - ffb09758", device_id: "96734c190dad42b4422", platform: "Windows", allocated_ip: "172.16.0.53/32", tunnel_status: "Shield", device_status: "-", configured_on: "2025-02-22", handshake: "9h:28m:13s", received_data: "568MB", transformed_data: "4GB" },
        { device_name: "PL Connect - ffb09758", device_id: "96734c190dad42b4422", platform: "Windows", allocated_ip: "172.16.0.53/32", tunnel_status: "Shield", device_status: "-", configured_on: "2025-02-22", handshake: "9h:28m:13s", received_data: "568MB", transformed_data: "4GB" },
        { device_name: "PL Connect - ffb09758", device_id: "96734c190dad42b4422", platform: "Windows", allocated_ip: "172.16.0.53/32", tunnel_status: "Shield", device_status: "-", configured_on: "2025-02-22", handshake: "9h:28m:13s", received_data: "568MB", transformed_data: "4GB" },
        { device_name: "PL Connect - ffb09758", device_id: "96734c190dad42b4422", platform: "Windows", allocated_ip: "172.16.0.53/32", tunnel_status: "Shield", device_status: "-", configured_on: "2025-02-22", handshake: "9h:28m:13s", received_data: "568MB", transformed_data: "4GB" },
        { device_name: "PL Connect - ffb09758", device_id: "96734c190dad42b4422", platform: "Windows", allocated_ip: "172.16.0.53/32", tunnel_status: "Shield", device_status: "-", configured_on: "2025-02-22", handshake: "9h:28m:13s", received_data: "568MB", transformed_data: "4GB" },
        { device_name: "PL Connect - ffb09758", device_id: "96734c190dad42b4422", platform: "Windows", allocated_ip: "172.16.0.53/32", tunnel_status: "Shield", device_status: "-", configured_on: "2025-02-22", handshake: "9h:28m:13s", received_data: "568MB", transformed_data: "4GB" },
        { device_name: "PL Connect - ffb09758", device_id: "96734c190dad42b4422", platform: "Windows", allocated_ip: "172.16.0.53/32", tunnel_status: "Shield", device_status: "-", configured_on: "2025-02-22", handshake: "9h:28m:13s", received_data: "568MB", transformed_data: "4GB" },
        { device_name: "PL Connect - ffb09758", device_id: "96734c190dad42b4422", platform: "Windows", allocated_ip: "172.16.0.53/32", tunnel_status: "Shield", device_status: "-", configured_on: "2025-02-22", handshake: "9h:28m:13s", received_data: "568MB", transformed_data: "4GB" },
        { device_name: "PL Connect - ffb09758", device_id: "96734c190dad42b4422", platform: "Windows", allocated_ip: "172.16.0.53/32", tunnel_status: "Shield", device_status: "-", configured_on: "2025-02-22", handshake: "9h:28m:13s", received_data: "568MB", transformed_data: "4GB" },
        { device_name: "PL Connect - ffb09758", device_id: "96734c190dad42b4422", platform: "Windows", allocated_ip: "172.16.0.53/32", tunnel_status: "Shield", device_status: "-", configured_on: "2025-02-22", handshake: "9h:28m:13s", received_data: "568MB", transformed_data: "4GB" },
        { device_name: "PL Connect - ffb09758", device_id: "96734c190dad42b4422", platform: "Windows", allocated_ip: "172.16.0.53/32", tunnel_status: "Shield", device_status: "-", configured_on: "2025-02-22", handshake: "9h:28m:13s", received_data: "568MB", transformed_data: "4GB" },
        { device_name: "PL Connect - ffb09758", device_id: "96734c190dad42b4422", platform: "Windows", allocated_ip: "172.16.0.53/32", tunnel_status: "Shield", device_status: "-", configured_on: "2025-02-22", handshake: "9h:28m:13s", received_data: "568MB", transformed_data: "4GB" },
        { device_name: "PL Connect - ffb09758", device_id: "96734c190dad42b4422", platform: "Windows", allocated_ip: "172.16.0.53/32", tunnel_status: "Shield", device_status: "-", configured_on: "2025-02-22", handshake: "9h:28m:13s", received_data: "568MB", transformed_data: "4GB" },
        { device_name: "PL Connect - ffb09758", device_id: "96734c190dad42b4422", platform: "Windows", allocated_ip: "172.16.0.53/32", tunnel_status: "Shield", device_status: "-", configured_on: "2025-02-22", handshake: "9h:28m:13s", received_data: "568MB", transformed_data: "4GB" },
        // Add more data...
      ],

    };
  },
  computed: {
    profileImage() {
      const profile = this.$store.state.account.userDetails.profile;
      return profile ? `https://api.privateline.io/uploads/${profile}` : "";
    },
    deviceListData() {
      return this.$store.state.account.deviceList.rows || [];
    },

    IsAccIdLogin: function () {
      let value = false;
      if (
        this.IsSessionInfoReceived &&
        this.$store.state.account != null &&
        this.$store.state.account.session != null &&
        this.$store.state.account.session.AccountID != null &&
        this.$store.state.account.session.AccountID !== ""
      ) {
        const accountId = this.$store.state.account.session.AccountID;
        // Check if accountId matches the pattern XXXX-XXXX-XXXX. Characters '0', 'O', 'I' are forbidden.
        const accountIdPattern =
          /^(a-)?([1-9A-HJ-NP-Z]{4}-){2}[1-9A-HJ-NP-Z]{4}$/;
        value = accountIdPattern.test(accountId);
      }
      return value;
    },

    filteredData() {
      return this.deviceListData.filter(device =>
        device.device_name.toLowerCase().includes(this.searchQuery.toLowerCase())
      );
    },
    paginatedData() {
      const start = (this.currentPage - 1) * this.itemsPerPage;
      const end = start + this.itemsPerPage;
      return this.filteredData.slice(start, end);
    },
    totalPages() {
      return Math.ceil(this.filteredData.length / this.itemsPerPage);
    },
  },
  mounted() {
    //this.accountStatusRequest();
    this.profileData();
    this.deviceList();
    this.getSubscriptionData();
    this.waitForSessionInfo();
  },
  methods: {
    async accountStatusRequest() {
      await sender.SessionStatus();
    },
    async waitForSessionInfo() {
      // wait for 10s for session information to come through
      for (let i = 0; !this.IsSessionInfoReceived && i < 40; i++) {
        await new Promise((r) => setTimeout(r, 250));
      }

      // if session info received - trigger rendering account ID QR code
      if (this.IsSessionInfoReceived) this.computeAndSetAccIdQrCode();
      else console.log("waitForSessionInfo() timed out");
    },

    async deviceList() {
      try {
        this.isProcessing = true;

        this.apiDeviceListTimeout = setTimeout(() => {
          throw Error("Device List API Time Out");
        }, 10 * 1000);
        await sender.DeviceList();
      } catch (err) {
        console.log({ err });
        sender.showMessageBoxSync({
          type: "error",
          buttons: ["OK"],
          message: "API Error",
          detail: `Device list couldn't be fetched at this moment, please check your internet connection!`,
        });
      } finally {
        this.isProcessing = false;
        clearTimeout(this.apiDeviceListTimeout);
        this.apiDeviceListTimeout = null;
      }
    },

    formatDate(date) {
      const options = { year: "numeric", month: "long", day: "numeric" };
      return new Date(date).toLocaleDateString(undefined, options);
    },
    prevPage() {
      if (this.currentPage > 1) this.currentPage--;
    },
    nextPage() {
      if (this.currentPage < this.totalPages) this.currentPage++;
    },
    changePage(page) {
      if (page >= 1 && page <= this.totalPages) {
        this.currentPage = page;
      }
    }
  }
};
</script>

<style scoped lang="scss">
@import "@/components/scss/constants";

.defColor {
  @extend .settingsDefaultTextColor;
}

.device-list {
  width: 500px;
  height: 400px;
  overflow-x: auto;
}

.device-list table {
  width: 100%;
  border-collapse: collapse;
  border-radius: 10px;
  overflow: hidden;
  box-shadow: 0px 4px 10px rgba(0, 0, 0, 0.1);
}

.device-list th {
  min-width: 50px;
  background-color: grey;
  color: white;
  padding: 8px;
  text-align: left;
  font-weight: bold;
  position: sticky;
  top: 0;
  z-index: 10;
  font-size: 10px;
}

.device-name {
  min-width: 150px;
}

.device-list td {
  font-size: 12px;
  padding: 5px;
  border-bottom: 1px solid #a0a0a0;

}

// .device-list tr:nth-child(even) {
//   background-color: #f9f9f9;
// }

.status-shield {
  // background-color: #28a745;
  color: #28a745;
  // padding: 3px 10px;
  // border-radius: 4px;
  font-size: 12px;
  font-weight: bold;
}

.action-icons {
  display: flex;
  gap: 10px;
}

.icon img {
  cursor: pointer;
  transition: transform 0.2s ease-in-out;
}

.icon img:hover {
  transform: scale(1.1);
}

.pagination {
  display: flex;
  justify-content: center;
  margin-top: 15px;
  gap: 5px;
}

.pagination button {
  padding: 8px 12px;
  border: none;
  background-color: #662d91;
  color: white;
  cursor: pointer;
  border-radius: 4px;
  transition: background 0.2s;
}

.pagination button:disabled {
  background-color: #aaa;
  cursor: not-allowed;
}

.pagination button.active {
  background-color: #662d91;
}

// Search 
.search-container {
  display: flex;
  align-items: center;
  margin-bottom: 10px;
}

.search-input {
  width: 200px;
  padding: 8px;
  font-size: 14px;
  border: 1px solid #ccc;
  border-radius: 4px;
  outline: none;
  transition: border-color 0.3s;
}

.search-input:focus {
  border-color: #ccc;
}
</style>
