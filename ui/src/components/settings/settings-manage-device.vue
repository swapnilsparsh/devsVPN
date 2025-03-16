<template>
  <div class="flexColumn" style="justify-content: space-between; width: 100%">
    <div class="flexColumn">
      <div class="flexRow">
        <div class="settingsTitle">Manage Device</div>
      </div>

      <!-- Device List Start -->
      <div class="device-limit-container">
        <!-- Search Input -->
        <div class="search-container">
          <input type="text" v-model="searchQuery" placeholder="Search" class="search-input" />
        </div>

        <!-- Table Start-->
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
                <th class="status-width">Tunnel Status</th>
                <th>Device Status</th>
                <th>Configured On</th>
                <th>Handshake</th>
                <th>Received Data</th>
                <th class="device-name">Sent Data</th>
                <!-- <th>Action</th> -->
              </tr>
            </thead>
            <tbody>
              <tr v-if="isLoading">
                <td colspan="12">
                  <div class="shimmer-wrapper">
                    <ShimmerEffect v-for="i in 5" :key="i" :width="'100%'" :height="'20px'" />
                  </div>
                </td>
              </tr>
              <tr v-else v-for="(device, index) in devicePageList" :key="device.device_id">
                <td style="width: 30px;">{{ index + 1 + (currentPage - 1) * itemsPerPage }}</td>
                <td>
                  <span class="icon view-icon" style="margin-right: 15px;">
                    <img style="vertical-align: middle" src="@/assets/eye-open.svg" @click="viewDetails(device)" />
                  </span>
                  <span class="icon delete-icon" style="display: inline-block;" @click="removeDevice(device.id)">
                    <img style="vertical-align: middle" src="@/assets/delete.png" height="17" width="17" />
                  </span>
                </td>
                <td class="device-name">{{ device.device_name }}</td>
                <td>{{ device.device_id }}</td>
                <td>{{ device.type }}</td>
                <td>{{ device.allocated_ip }}</td>
                <td class="status-width"><span class="status-shield">Shield</span></td>
                <td class="device-name">{{ device.isConnected ? "Connected" : '-' }}</td>
                <td class="device-name">{{ formatDate(device.createdAt) }}</td>
                <td class="device-name">{{ device.handshake }}</td>
                <td class="device-name">{{ convertBitsToReadable(device.rx) }}</td>
                <td class="device-name">{{ convertBitsToReadable(device.tx) }}</td>
              </tr>
            </tbody>
          </table>
        </div>
        <!-- Pagination Controls -->
        <div class="pagination">
          <button @click="changePage(1)" :disabled="currentPage === 1">First</button>
          <button @click="changePage(currentPage - 1)" :disabled="currentPage === 1">«</button>
          <button v-if="currentPage > 2" @click="changePage(1)">1</button>
          <span v-if="currentPage > 3">...</span>
          <button v-if="currentPage > 1" @click="changePage(currentPage - 1)">{{ currentPage - 1 }}</button>
          <button class="active">{{ currentPage }}</button>
          <button v-if="currentPage < totalPages" @click="changePage(currentPage + 1)">{{ currentPage + 1 }}</button>
          <span v-if="currentPage < totalPages - 2">...</span>
          <button v-if="currentPage < totalPages - 1" @click="changePage(totalPages)">{{ totalPages }}</button>
          <button @click="changePage(currentPage + 1)" :disabled="currentPage >= totalPages">»</button>
          <button @click="changePage(totalPages)" :disabled="currentPage === totalPages">Last</button>
        </div>
        <!-- Table End  -->
      </div>
      <!-- Device List END -->

      <!-- View Details Popup Start -->
      <ComponentDialog ref="viewDeviceDetails" header="Device Details">
        <div>
          <div class="device-info">
            <div class="section">
              <p><strong>Device ID:</strong> {{ this.showDetails?.device_id }}</p>
              <p><strong>Device Name:</strong> {{ this.showDetails?.device_name }}</p>
              <!-- <p><strong>Type:</strong> {{this.showDetails?.type}}</p>
              <p><strong>Device IP:</strong> {{this.showDetails?.device_ip}}</p>
              <p><strong>Allocated IP:</strong> {{this.showDetails?.allocated_ip}}</p> -->
            </div>
            <div class="section">
              <p><strong>Public Key:</strong></p>
              <p class="code">{{ this.showDetails?.public_key }}</p>
              <p><strong>Interface Public Key:</strong></p>
              <p class="code">{{ this.showDetails?.interface_publickey }}</p>
            </div>
            <div class="section">
              <p><strong>DNS:</strong> {{ this.showDetails?.DNS }}</p>
              <p><strong>Allowed IPs:</strong></p>
              <p class="small-text">
                {{ this.showDetails?.allowedIPs }}
              </p>
              <p><strong>Endpoint:</strong> {{ this.showDetails?.endpoint }}</p>
            </div>
            <div class="section">
              <!-- <p><strong>Status:</strong> <span class="status active">{{this.showDetails?.status}}</span></p>
              <p><strong>Created At:</strong> {{this.showDetails?.createdAt}}</p> -->
              <p><strong>Current Endpoint Address:</strong> {{ this.showDetails?.current_endpoint_address }}</p>
              <!-- <p><strong>Active Tunnel:</strong> {{this.showDetails?.keep_alive}}</p> -->
            </div>
            <!-- <div class="section">
              <p><strong>RX:</strong> {{this.showDetails?.rx}}</p>
              <p><strong>TX:</strong> {{this.showDetails?.tx}}</p>
              <p><strong>Handshake:</strong> {{this.showDetails?.handshake}}</p>
            </div> -->

            <!-- <div class="status-indicator">
              <span>Connected:</span>
              <div class="dot disconnected"></div>
            </div> -->
          </div>
        </div>
      </ComponentDialog>
      <!-- View Details Popup End -->
    </div>
  </div>
</template>

<script>

import ShimmerEffect from "../Shimmer";
import ComponentDialog from "@/components/component-dialog.vue";
const sender = window.ipcSender;

export default {
  components: {
    ShimmerEffect,
    ComponentDialog
  },
  data: function () {
    return {
      isProcessing: true,

      searchQuery: "",
      currentPage: 1,
      totalCount: 0,
      itemsPerPage: 10,
      deviceListData: [],
      showDetails: {},
      debounceTimeout: null,
      isDeviceListLoading: true
    };
  },
  computed: {
    devicePageList() {
      return this.deviceListData;
    },
    totalPages() {
      return Math.ceil(this.totalCount / this.itemsPerPage);
    },
    isLoading() {
      return this.isDeviceListLoading
    }
  },
  mounted() {
    this.deviceList(this.searchQuery, this.currentPage, this.itemsPerPage, 0);
  },
  methods: {
    async deviceList(search = '', page = 1, limit = 10, deleteId = 0) {
      try {
        this.isProcessing = true;
        this.isDeviceListLoading = true;

        const deviceListResp = await sender.DeviceList(search, page, limit, deleteId);
        this.isDeviceListLoading = false;
        this.deviceListData = deviceListResp.rows;
        this.totalCount = deviceListResp?.count;
        console.log(deviceListResp)
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
      }
    },

    convertBitsToReadable(bit) {
      const parsedBit = typeof bit === "string" ? parseFloat(bit) : bit;
      if (isNaN(parsedBit) || parsedBit < 0) return "-";

      const units = ["bps", "Kb", "Mb", "Gb", "Tb", "Pb", "Eb"];
      let size = parsedBit;
      let unitIndex = 0;

      while (size >= 1024 && unitIndex < units.length - 1) {
        size /= 1024;
        unitIndex++;
      }

      return `${size.toFixed(size < 10 ? 2 : 1)} ${units[unitIndex]}`;
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
    async changePage(page) {
      if (page >= 1 && page <= this.totalPages) {
        this.currentPage = page;
        await this.deviceList(this.searchQuery, this.currentPage, this.itemsPerPage, 0);
      }
    },
    async removeDevice(deleteId) {
      let ret = await sender.showMessageBox(
        {
          type: "warning",
          buttons: ["OK", "Cancel"],
          message: "Are you sure? You want to remove this device",
          detail: ``,
        },
        true
      );
      if (ret.response == 1) return; // cancel
      if (ret.response == 0) {
        // Call action for delete
        console.log("delete")
        // deleteId
        await this.deviceList(this.searchQuery, this.currentPage, this.itemsPerPage, deleteId);

      }

    },
    viewDetails(device) {
      this.$refs.viewDeviceDetails.showModal()
      this.showDetails = device;
    }
  },
  watch: {
    searchQuery(newQuery) {
      clearTimeout(this.debounceTimeout); // Clear previous timeout

      this.debounceTimeout = setTimeout(() => {
        this.currentPage = 1; // Reset to first page on search
        const trimmedQuery = newQuery.trim();

        if (trimmedQuery.length > 0) {
          this.deviceList(trimmedQuery, this.currentPage, this.itemsPerPage, 0);
        } else if (trimmedQuery.length == 0) {
          this.deviceList('', this.currentPage, this.itemsPerPage, 0); // Reset the list
        }
      }, 300); // Adjust debounce time as needed
    },
  },
  beforeUnmount() {
    clearTimeout(this.debounceTimeout); // Cleanup on component unmount
  },
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

.status-shield {
  color: #28a745;
  font-size: 12px;
  font-weight: bold;
}

.status-width {
  min-width: 100px;
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

// ========= device info card =======
.device-info {
  background: inherit;
  padding: 20px;
  border-radius: 10px;
  box-shadow: 0px 4px 10px rgba(0, 0, 0, 0.1);
  width: 400px;
}

h2 {
  text-align: center;
  font-size: 1.5rem;
  color: #333;
  margin-bottom: 15px;
}

.section {
  border-bottom: 1px solid #ddd;
  padding-bottom: 10px;
  margin-bottom: 10px;
}

.section p {
  margin: 5px 0;
  font-size: 14px;
}

.code {
  font-size: 12px;
  background-color: #eee;
  color: #333;
  padding: 5px;
  border-radius: 5px;
  word-break: break-all;
}

.small-text {
  font-size: 12px;
  color: #666;
}

.status {
  font-weight: bold;
  padding: 3px 7px;
  border-radius: 5px;
}

.status.active {
  background-color: #28a745;
  color: white;
}

.status-indicator {
  display: flex;
  align-items: center;
  margin-top: 10px;
}

.status-indicator span {
  margin-right: 10px;
}

.dot {
  width: 12px;
  height: 12px;
  border-radius: 50%;
}

.dot.connected {
  background-color: green;
}

.dot.disconnected {
  background-color: red;
}
.shimmer-wrapper {
  display: flex;
  flex-direction: column;
  gap: 10px;
  padding: 10px;
}
</style>
