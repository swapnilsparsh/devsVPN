<template>
  <div class="flexColumn" style="justify-content: space-between; width: 100%">
    <div class="flexColumn">
      <div class="flexRow">
        <div class="settingsTitle">Manage Devices</div>
      </div>

      <!-- Device List Start -->
      <div class="device-limit-container">
        <!-- Search Input -->
        <div class="search-container">
          <input
            type="text"
            v-model="searchQuery"
            placeholder="Search"
            class="search-input"
            :disabled="hasNetworkError"
            :title="
              hasNetworkError
                ? 'Search is disabled due to network connectivity issues'
                : ''
            "
          />
        </div>

        <!-- Table Start-->
        <div class="device-list">
          <table>
            <thead>
              <tr>
                <th style="min-width: 32px">Sr. No.</th>
                <th>Action</th>
                <th>Device Name</th>
                <th>Platform</th>
                <th>Device Status</th>
                <th>Configured On</th>
                <th>Handshake</th>
              </tr>
            </thead>
            <tbody>
              <tr v-if="isLoading">
                <td colspan="12">
                  <div class="shimmer-wrapper">
                    <ShimmerEffect
                      v-for="i in 5"
                      :key="i"
                      :width="'100%'"
                      :height="'20px'"
                    />
                  </div>
                </td>
              </tr>
              <tr v-else-if="devicePageList.length === 0">
                <td colspan="12">
                  <div class="no-results">
                    <p v-if="hasNetworkError">Network Connection Error</p>
                    <p v-else-if="searchQuery">No devices found</p>
                    <p v-else>Unable to load devices</p>
                    <p class="no-results-detail" v-if="hasNetworkError">
                      Please check your internet connection and try again.
                      Search is temporarily disabled.
                      <br />
                      <button class="retry-button" @click="retryConnection">
                        Retry Connection
                      </button>
                    </p>
                    <p class="no-results-detail" v-else-if="searchQuery">
                      Try adjusting your search criteria
                    </p>
                    <p class="no-results-detail" v-else>
                      Please check your network connection and try again
                    </p>
                  </div>
                </td>
              </tr>
              <tr
                v-else
                v-for="(device, index) in devicePageList"
                :key="device.device_id"
                :class="{ 'current-device-row': isCurrentDevice(device.id) }"
                :title="
                  isCurrentDevice(device.id)
                    ? 'This is your current device'
                    : ''
                "
              >
                <td>
                  {{ index + 1 + (currentPage - 1) * itemsPerPage }}
                </td>
                <td>
                  <span class="icon view-icon" style="margin-right: 15px">
                    <img
                      style="vertical-align: middle"
                      src="@/assets/eye-open.svg"
                      @click="viewDetails(device)"
                      title="View Details"
                      role="button"
                      aria-label="View device details"
                    />
                  </span>
                  <span
                    v-if="!isCurrentDevice(device.id)"
                    class="icon delete-icon"
                    style="display: inline-block"
                    @click="removeDevice(device.id)"
                    title="Delete"
                    role="button"
                    aria-label="Delete device"
                  >
                    <img
                      style="vertical-align: middle"
                      src="@/assets/delete.png"
                      height="17"
                      width="17"
                    />
                  </span>
                  <span
                    v-else
                    class="icon delete-icon-disabled"
                    style="display: inline-block"
                    title="Cannot delete current device"
                  >
                    <img
                      style="vertical-align: middle; opacity: 0.3"
                      src="@/assets/delete.png"
                      height="17"
                      width="17"
                    />
                  </span>
                </td>
                <!-- Update the device name column to include a visual indicator -->
                <td>
                  {{ device.device_name }}
                  <span
                    v-if="isCurrentDevice(device.id)"
                    class="current-device-indicator"
                  >
                    (Current)
                  </span>
                </td>
                <td>{{ device.type }}</td>
                <td>{{ device.isConnected ? "Connected" : "-" }}</td>
                <td>{{ formatDate(device.createdAt) }}</td>
                <td>{{ device.handshake }}</td>
              </tr>
            </tbody>
          </table>
        </div>
        <!-- Pagination Controls -->
        <div class="pagination" v-if="!hasNetworkError">
          <button
            @click="changePage(1)"
            :disabled="currentPage === 1"
            title="First Page"
          >
            First
          </button>
          <button
            @click="changePage(currentPage - 1)"
            :disabled="currentPage === 1"
            title="Previous Page"
          >
            «
          </button>
          <button v-if="currentPage > 2" @click="changePage(1)">1</button>
          <span v-if="currentPage > 3">...</span>
          <button v-if="currentPage > 1" @click="changePage(currentPage - 1)">
            {{ currentPage - 1 }}
          </button>
          <button class="active" title="Current Page">{{ currentPage }}</button>
          <button
            v-if="currentPage < totalPages"
            @click="changePage(currentPage + 1)"
          >
            {{ currentPage + 1 }}
          </button>
          <span v-if="currentPage < totalPages - 2">...</span>
          <button
            v-if="currentPage < totalPages - 1"
            @click="changePage(totalPages)"
          >
            {{ totalPages }}
          </button>
          <button
            @click="changePage(currentPage + 1)"
            :disabled="currentPage >= totalPages"
            title="Next Page"
          >
            »
          </button>
          <button
            @click="changePage(totalPages)"
            :disabled="currentPage === totalPages"
            title="Last Page"
          >
            Last
          </button>
        </div>
        <!-- Table End  -->
      </div>
      <!-- Device List END -->

      <!-- View Details Popup Start -->
      <ComponentDialog ref="viewDeviceDetails" header="Device Details">
        <div>
          <div class="device-info">
            <div
              v-if="isCurrentDevice(showDetails?.id)"
              class="current-device-tag"
            >
              Current Device
            </div>
            <div class="section">
              <p>
                <strong>Device ID:</strong> {{ this.showDetails?.device_id }}
              </p>
              <p>
                <strong>Device Name:</strong>
                {{ this.showDetails?.device_name }}
              </p>
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
              <p>
                {{ this.showDetails?.allowedIPs }}
              </p>
              <p><strong>Endpoint:</strong> {{ this.showDetails?.endpoint }}</p>
              <p>
                <strong>Allocated IP</strong>
                {{
                  this.showDetails?.allocated_ip
                    ? formatIP(this.showDetails.allocated_ip)
                    : "-"
                }}
              </p>
            </div>
            <div class="section">
              <p>
                <strong>Current Endpoint Address:</strong>
                {{ this.showDetails?.current_endpoint_address }}
              </p>
            </div>
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
    ComponentDialog,
  },
  data: function () {
    return {
      isProcessing: true,
      searchQuery: "",
      currentPage: 1,
      totalCount: 0,
      itemsPerPage: 5,
      deviceListData: [],
      showDetails: {},
      debounceTimeout: null,
      isDeviceListLoading: true,
      currentDeviceId: null,
      isDeleteDialogOpen: false,
      apiDeviceListTimeout: null,
      hasNetworkError: false,
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
      return this.isDeviceListLoading;
    },
  },
  mounted() {
    this.deviceList(
      this.searchQuery,
      this.currentPage,
      this.itemsPerPage,
      0
    ).then(() => {
      this.getCurrentDeviceId(); // Call this after initial device list is loaded
    });
  },
  activated() {
    // This lifecycle hook is called when the component becomes active
    // (useful for components used in keep-alive scenarios or tab switching)
    // Refresh the device list to check current network state
    if (this.hasNetworkError) {
      this.deviceList(this.searchQuery, this.currentPage, this.itemsPerPage, 0);
    }
  },
  methods: {
    async getCurrentDeviceId() {
      try {
        // Get WireGuard public key from store
        const wgPublicKey = this.$store.state.account.session.WgPublicKey;

        if (!wgPublicKey) {
          this.currentDeviceId = null;
          return;
        }

        // Check current page first
        let currentDevice = this.deviceListData.find(
          (device) =>
            device.public_key === wgPublicKey ||
            device.interface_publickey === wgPublicKey
        );

        if (currentDevice) {
          this.currentDeviceId = currentDevice.id;
          return;
        }

        // TODO: This logic needs to corrected.
        // If not found in current page, search all devices
        // if (this.totalCount > this.itemsPerPage) {
        //   try {
        //     const allDevicesResp = await sender.DeviceList(
        //       "",
        //       1,
        //       this.totalCount,
        //       0
        //     );

        //     if (allDevicesResp && allDevicesResp.rows) {
        //       currentDevice = allDevicesResp.rows.find(
        //         (device) =>
        //           device.public_key === wgPublicKey ||
        //           device.interface_publickey === wgPublicKey
        //       );

        //       if (currentDevice) {
        //         this.currentDeviceId = currentDevice.id;

        //         // Navigate to the page containing the current device
        //         const deviceIndex = allDevicesResp.rows.findIndex(
        //           (device) => device.id === currentDevice.id
        //         );

        //         if (deviceIndex !== -1) {
        //           const devicePage =
        //             Math.floor(deviceIndex / this.itemsPerPage) + 1;

        //           if (devicePage !== this.currentPage) {
        //             await this.changePage(devicePage);
        //           }
        //         }
        //       } else {
        //       }
        //     }
        //   } catch (error) {
        //     console.error("Error finding current device:", error);
        //   }
        // }
      } catch (error) {
        console.error("Error identifying current device:", error);
        this.currentDeviceId = null;
      }
    },
    isCurrentDevice(deviceId) {
      return deviceId === this.currentDeviceId;
    },
    async deviceList(search = "", page = 1, limit = 10, deleteId = 0) {
      try {
        this.isProcessing = true;
        this.isDeviceListLoading = true;
        // Don't reset hasNetworkError here - only reset it on successful API response

        this.apiDeviceListTimeout = setTimeout(() => {
          throw Error("Device List API Time Out");
        }, 10 * 1000);

        const deviceListResp = await sender.DeviceList(
          search,
          page,
          limit,
          deleteId
        );

        // Only reset network error if we get here (successful API response)
        this.hasNetworkError = false;

        this.deviceListData = deviceListResp.rows || [];
        this.totalCount = deviceListResp?.count || 0;

        // Check if current device is in the loaded devices
        const wgPublicKey = this.$store.state.account.session.WgPublicKey;
        if (wgPublicKey) {
          const currentDevice = this.deviceListData.find(
            (device) =>
              device.public_key === wgPublicKey ||
              device.interface_publickey === wgPublicKey
          );

          if (currentDevice) {
            this.currentDeviceId = currentDevice.id;
          }
        }

        this.isDeviceListLoading = false;
      } catch (err) {
        console.error("Error loading device list:", err);

        // Reset data on error
        this.deviceListData = [];
        this.totalCount = 0;
        this.isDeviceListLoading = false;

        // Set network error state for ALL errors - this is safer than trying to detect specific error types
        // We'll reset this only when we successfully get data
        this.hasNetworkError = true;

        // Check if this is a delete operation or regular list loading
        if (deleteId > 0) {
          // This was a delete operation
          const errorMessage =
            err?.split("=")[1]?.trim() ||
            "Unable to delete device due to connectivity issues. Please check your network connection.";
          sender.showMessageBoxSync({
            type: "error",
            buttons: ["OK"],
            message: "Network Error",
            detail: errorMessage,
          });
        } else {
          // This was a regular list loading operation
          sender.showMessageBoxSync({
            type: "error",
            buttons: ["OK"],
            message: "API Error",
            detail: `Device list couldn't be fetched at this moment, please check your internet connection!`,
          });
        }
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
    formatIP(ip) {
      if (!ip) return "-";
      return ip.replace("/32", "");
    },
    prevPage() {
      if (this.currentPage > 1) this.currentPage--;
    },
    nextPage() {
      if (this.currentPage < this.totalPages) this.currentPage++;
    },
    async changePage(page) {
      if (this.hasNetworkError) {
        return; // Don't allow page changes when there's a network error
      }

      if (page >= 1 && page <= this.totalPages) {
        this.currentPage = page;
        await this.deviceList(
          this.searchQuery,
          this.currentPage,
          this.itemsPerPage,
          0
        );
      }
    },
    async removeDevice(deleteId) {
      if (this.isDeleteDialogOpen) return;

      try {
        this.isDeleteDialogOpen = true;

        let ret = await sender.showMessageBox(
          {
            type: "warning",
            buttons: ["OK", "Cancel"],
            message: "Are you sure you want to delete this device?",
            detail: ``,
          },
          true
        );

        if (ret.response == 0) {
          // OK was clicked
          await this.deviceList(
            this.searchQuery,
            this.currentPage,
            this.itemsPerPage,
            deleteId
          );
        }
        // Cancel was clicked (or dialog was closed) - do nothing
      } catch (error) {
        console.error("Error showing delete confirmation:", error);
      } finally {
        this.isDeleteDialogOpen = false;
      }
    },
    viewDetails(device) {
      this.$refs.viewDeviceDetails.showModal();
      this.showDetails = device;
    },
    async retryConnection() {
      this.hasNetworkError = false;
      this.searchQuery = ""; // Clear search query
      await this.deviceList("", 1, this.itemsPerPage, 0);
    },
  },
  watch: {
    searchQuery(newQuery) {
      // Don't perform search if there's a network error
      if (this.hasNetworkError) {
        return;
      }

      clearTimeout(this.debounceTimeout); // Clear previous timeout

      this.debounceTimeout = setTimeout(() => {
        this.currentPage = 1; // Reset to first page on search
        const trimmedQuery = newQuery.trim();

        if (trimmedQuery.length > 0) {
          this.deviceList(trimmedQuery, this.currentPage, this.itemsPerPage, 0);
        } else if (trimmedQuery.length == 0) {
          this.deviceList("", this.currentPage, this.itemsPerPage, 0); // Reset the list
        }
      }, 300); // Adjust debounce time as needed
    },
  },
  beforeUnmount() {
    clearTimeout(this.debounceTimeout); // Cleanup on component unmount
    clearTimeout(this.apiDeviceListTimeout); // Cleanup API timeout
  },
};
</script>

<style scoped lang="scss">
@use "@/components/scss/constants";

.defColor {
  @extend .settingsDefaultTextColor;
}

.device-list {
  width: 100%;
  // width: calc(100% - 150px);
  height: auto;
  overflow: auto;
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

.device-list td {
  font-size: 12px;
  padding: 5px;
  border-bottom: 1px solid #a0a0a0;
}

// Add these new styles to your <style> section
.current-device-row {
  background-color: rgba(
    102,
    45,
    145,
    0.2
  ) !important; // Making this more visible against dark theme
  border-left: 3px solid #662d91;
  position: relative;
}

.current-device-row:hover {
  background-color: rgba(102, 45, 145, 0.3) !important;
}

.current-device-indicator {
  display: inline-block;
  margin-left: 5px;
  font-size: 10px;
  background-color: #662d91;
  color: white;
  padding: 1px 4px;
  border-radius: 4px;
  vertical-align: middle;
}

.current-device-tag {
  display: inline-block;
  background-color: #662d91;
  color: white;
  padding: 3px 8px;
  border-radius: 4px;
  font-size: 12px;
  margin-bottom: 10px;
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
  border: 1px solid #662d91;
  background-color: transparent;
  color: #662d91;
  cursor: pointer;
  border-radius: 4px;
  transition: background 0.2s;
}

.pagination button:hover {
  background-color: #662d91;
  color: white;
}

.pagination button:disabled {
  background-color: #a0a0a0;
  border: none;
  cursor: not-allowed;
  color: white;
}

.pagination button:disabled:hover {
  background-color: #a0a0a0;
  color: white;
}

.pagination button.active {
  background-color: inherit;
  color: white;
  background-color: #662d91;
  border: 1px solid #662d91;
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
  border: 1px solid #662d91;
  background-color: #a0a0a0;
  color: white;
  border-radius: 4px;
  outline: none;
  transition: border-color 0.3s;
}

.search-input:focus {
  border-color: #662d91;
}

.search-input::placeholder {
  color: white;
}

.search-input:disabled {
  background-color: #505050;
  border-color: #505050;
  color: #808080;
  cursor: not-allowed;
}

.search-input:disabled::placeholder {
  color: #808080;
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
  font-size: 13px;
}

.code {
  font-size: 12px;
  background-color: #eee;
  color: #333;
  padding: 5px;
  border-radius: 5px;
  word-break: break-all;
}

.shimmer-wrapper {
  display: flex;
  flex-direction: column;
  gap: 10px;
  padding: 10px;
}

.no-results {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 30px 0;
  width: 100%;
  text-align: center;
}

.no-results p {
  font-size: 16px;
  color: var(--text-color-details);
  margin: 5px 0;
}

.no-results-detail {
  font-size: 14px;
}

.retry-button {
  margin-top: 10px;
  padding: 8px 16px;
  background-color: #662d91;
  color: white;
  border: none;
  border-radius: 4px;
  cursor: pointer;
  font-size: 12px;
  transition: background-color 0.2s;
}

.retry-button:hover {
  background-color: #552378;
}
</style>
