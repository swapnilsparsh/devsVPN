<template>
  <div class="rageshake-test">
    <h2>Rageshake System Test</h2>
    
    <!-- Server Information -->
    <div class="server-info">
      <h3>Server Configuration</h3>
      <p><strong>Server URL:</strong> {{ serverUrl }}</p>
      <p><strong>Status:</strong> 
        <span :class="connectionStatusClass">{{ connectionStatus }}</span>
      </p>
    </div>



    <!-- Test Buttons -->
    <div class="test-buttons">
      <h3>Test Functions</h3>
      

      
      <button @click="testManualCrashReport" :disabled="isLoading">
        Test Manual Crash Report
      </button>
      
      <button @click="testExceptionCrashReport" :disabled="isLoading">
        Test Exception Report
      </button>
      
      <button @click="testRejectionCrashReport" :disabled="isLoading">
        Test Rejection Report
      </button>
      
      <button @click="testCollectReport" :disabled="isLoading">
        Test Collect Report
      </button>
    </div>

    <!-- Results -->
    <div v-if="testResults.length > 0" class="test-results">
      <h3>Test Results</h3>
      <div v-for="(result, index) in testResults" :key="index" class="result-item">
        <strong>{{ result.test }}:</strong> 
        <span :class="result.success ? 'success' : 'error'">
          {{ result.success ? 'SUCCESS' : 'FAILED' }}
        </span>
        <p v-if="result.message">{{ result.message }}</p>
      </div>
    </div>
  </div>
</template>

<script>
const sender = window.ipcSender;

export default {
  name: 'RageshakeTest',
  data() {
    return {
      lastResult: null,
      serverUrl: 'https://logs.privateline.io/rageshake',
      connectionStatus: 'unknown',
      connectionStatusText: 'Not tested',

      isLoading: false,
      testResults: []
    };
  },
  computed: {
    connectionStatusClass() {
      if (this.connectionStatus === 'success') return 'success';
      if (this.connectionStatus === 'error') return 'error';
      if (this.connectionStatus === 'testing') return 'testing';
      return 'unknown';
    }
  },
  methods: {


    async testManualCrashReport() {
      try {
        const result = await sender.GenerateCrashReport('manual', {
          testData: 'This is a manual test crash report',
          timestamp: new Date().toISOString()
        });
        this.lastResult = result;
        console.log('Manual crash report result:', result);
      } catch (error) {
        console.error('Error generating manual crash report:', error);
        this.lastResult = { error: error.message };
      }
    },

    async testExceptionCrashReport() {
      try {
        const result = await sender.GenerateCrashReport('uncaught_exception', {
          error: 'Test exception error',
          stack: 'Test stack trace',
          component: 'RageshakeTest.vue'
        });
        this.lastResult = result;
        console.log('Exception crash report result:', result);
      } catch (error) {
        console.error('Error generating exception crash report:', error);
        this.lastResult = { error: error.message };
      }
    },

    async testRejectionCrashReport() {
      try {
        const result = await sender.GenerateCrashReport('unhandled_rejection', {
          reason: 'Test rejection reason',
          promise: 'Test promise info',
          component: 'RageshakeTest.vue'
        });
        this.lastResult = result;
        console.log('Rejection crash report result:', result);
      } catch (error) {
        console.error('Error generating rejection crash report:', error);
        this.lastResult = { error: error.message };
      }
    },

    async testCollectReport() {
      try {
        const result = await sender.CollectCrashReport('manual', {
          testData: 'This is test data for collection',
          timestamp: new Date().toISOString()
        });
        this.lastResult = result;
        console.log('Collect crash report result:', result);
      } catch (error) {
        console.error('Error collecting crash report:', error);
        this.lastResult = { error: error.message };
      }
    },



    getStatusClass(status) {
      if (status === 'success') return 'success';
      if (status === 'error') return 'error';
      if (status === 'warning') return 'warning';
      if (status === 'info') return 'info';
      return 'unknown';
    }
  }
};
</script>

<style scoped lang="scss">
.rageshake-test {
  padding: 20px;
  max-width: 800px;
  margin: 0 auto;
}

.server-info {
  background-color: #f8f9fa;
  border: 1px solid #dee2e6;
  border-radius: 4px;
  padding: 15px;
  margin-bottom: 20px;
  
  h3 {
    margin-top: 0;
    margin-bottom: 10px;
    color: #495057;
  }
  
  p {
    margin: 5px 0;
    font-size: 14px;
  }
  
  .success {
    color: #28a745;
    font-weight: bold;
  }
  
  .error {
    color: #dc3545;
    font-weight: bold;
  }
  
  .testing {
    color: #ffc107;
    font-weight: bold;
  }
  
  .unknown {
    color: #6c757d;
    font-weight: bold;
  }
}



.test-buttons {
  display: flex;
  flex-direction: column;
  gap: 10px;
  margin-bottom: 20px;

  h3 {
    margin-top: 0;
    margin-bottom: 10px;
    color: #495057;
  }
}

.test-btn {
  padding: 10px 15px;
  background-color: #007bff;
  color: white;
  border: none;
  border-radius: 4px;
  cursor: pointer;
  font-size: 14px;
  
  &:hover {
    background-color: #0056b3;
  }
  
  &:active {
    background-color: #004085;
  }
  
  &.connection-btn {
    background-color: #28a745;
    
    &:hover {
      background-color: #218838;
    }
    
    &:active {
      background-color: #1e7e34;
    }
  }

  &:disabled {
    background-color: #ccc;
    cursor: not-allowed;
    color: #888;
  }
}

.test-results {
  background-color: #f8f9fa;
  border: 1px solid #dee2e6;
  border-radius: 4px;
  padding: 15px;
  margin-top: 20px;
  
  h3 {
    margin-top: 0;
    margin-bottom: 10px;
    color: #495057;
  }
  
  .result-item {
    margin-bottom: 10px;
    padding-bottom: 10px;
    border-bottom: 1px dashed #eee;

    &:last-child {
      border-bottom: none;
      padding-bottom: 0;
    }

    strong {
      font-weight: bold;
      color: #343a40;
    }

    .success {
      color: #28a745;
    }

    .error {
      color: #dc3545;
    }
  }
}
</style> 