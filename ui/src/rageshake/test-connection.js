/**
 * Rageshake Server Connection Test
 * 
 * This script tests the connection to the Rageshake server
 * and verifies that the endpoint is accessible.
 */

import { createRageshakeAPI, testRageshakeServer } from './api.js';
import { getUploadURL, getServerConfig } from './config.js';

/**
 * Test the connection to the Rageshake server
 * @returns {Promise<Object>} Test result object
 */
export async function testRageshakeConnection() {
  const api = createRageshakeAPI();
  return await api.testConnection();
}

/**
 * Test with a sample crash report payload
 * @returns {Promise<Object>} Test result object
 */
export async function testRageshakeUpload() {
  const api = createRageshakeAPI();
  return await api.testSubmission();
}

/**
 * Run all connection tests
 * @returns {Promise<Object>} Combined test results
 */
export async function runAllTests() {
  console.log('=== Rageshake Server Connection Tests ===');
  
  const connectionTest = await testRageshakeConnection();
  const uploadTest = await testRageshakeUpload();
  
  const results = {
    timestamp: new Date().toISOString(),
    serverConfig: getServerConfig(),
    connectionTest,
    uploadTest,
    overallSuccess: connectionTest.success && uploadTest.success
  };
  
  console.log('\n=== Test Results Summary ===');
  console.log(`Connection Test: ${connectionTest.success ? 'PASS' : 'FAIL'}`);
  console.log(`Upload Test: ${uploadTest.success ? 'PASS' : 'FAIL'}`);
  console.log(`Overall: ${results.overallSuccess ? 'PASS' : 'FAIL'}`);
  
  if (!results.overallSuccess) {
    console.log('\n=== Error Details ===');
    if (connectionTest.error) {
      console.log(`Connection Error: ${connectionTest.error}`);
    }
    if (uploadTest.error) {
      console.log(`Upload Error: ${uploadTest.error}`);
    }
  }
  
  return results;
}

// Export for use in other modules
export default {
  testRageshakeConnection,
  testRageshakeUpload,
  runAllTests
}; 