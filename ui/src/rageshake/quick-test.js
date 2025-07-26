/**
 * Quick Rageshake System Test
 * 
 * This script provides a quick way to test if the Rageshake system
 * is ready for crash reporting and log submission.
 */

import { createRageshakeAPI } from './api.js';
import { getUploadURL } from './config.js';

/**
 * Quick system readiness test
 * @returns {Promise<Object>} Test results
 */
export async function quickSystemTest() {
  const results = {
    timestamp: new Date().toISOString(),
    serverUrl: getUploadURL(),
    tests: {},
    overallStatus: 'unknown'
  };

  console.log('🔍 Quick Rageshake System Test');
  console.log(`📡 Server URL: ${results.serverUrl}`);
  console.log('');

  try {
    // Test 1: Configuration
    console.log('✅ Testing configuration...');
    try {
      const api = createRageshakeAPI();
      results.tests.configuration = { status: 'passed', message: 'Configuration loaded successfully' };
      console.log('   ✓ Configuration OK');
    } catch (error) {
      results.tests.configuration = { status: 'failed', message: error.message };
      console.log('   ✗ Configuration failed:', error.message);
    }

    // Test 2: Server connectivity
    console.log('🌐 Testing server connectivity...');
    try {
      const api = createRageshakeAPI();
      const connectionTest = await api.testConnection();
      
      if (connectionTest.success) {
        results.tests.connectivity = { 
          status: 'passed', 
          message: `Server accessible (${connectionTest.status})` 
        };
        console.log(`   ✓ Server accessible (${connectionTest.status})`);
      } else {
        results.tests.connectivity = { 
          status: 'failed', 
          message: connectionTest.error 
        };
        console.log('   ✗ Server connectivity failed:', connectionTest.error);
      }
    } catch (error) {
      results.tests.connectivity = { status: 'failed', message: error.message };
      console.log('   ✗ Server connectivity failed:', error.message);
    }

    // Test 3: API submission
    console.log('📤 Testing API submission...');
    try {
      const api = createRageshakeAPI();
      const testResult = await api.testSubmission();
      
      if (testResult.success) {
        results.tests.submission = { 
          status: 'passed', 
          message: `Test submission successful${testResult.reportId ? ` (ID: ${testResult.reportId})` : ''}` 
        };
        console.log(`   ✓ Test submission successful${testResult.reportId ? ` (ID: ${testResult.reportId})` : ''}`);
      } else {
        results.tests.submission = { 
          status: 'failed', 
          message: testResult.error 
        };
        console.log('   ✗ Test submission failed:', testResult.error);
      }
    } catch (error) {
      results.tests.submission = { status: 'failed', message: error.message };
      console.log('   ✗ Test submission failed:', error.message);
    }

    // Determine overall status
    const failedTests = Object.values(results.tests).filter(test => test.status === 'failed');
    const passedTests = Object.values(results.tests).filter(test => test.status === 'passed');

    if (failedTests.length === 0) {
      results.overallStatus = 'ready';
      console.log('');
      console.log('🎉 SYSTEM IS READY FOR CRASH REPORTING!');
      console.log(`   ✓ All ${passedTests.length} tests passed`);
    } else if (passedTests.length > 0) {
      results.overallStatus = 'partial';
      console.log('');
      console.log('⚠️  SYSTEM HAS ISSUES - PARTIAL FUNCTIONALITY');
      console.log(`   ✓ ${passedTests.length} tests passed`);
      console.log(`   ✗ ${failedTests.length} tests failed`);
    } else {
      results.overallStatus = 'failed';
      console.log('');
      console.log('❌ SYSTEM IS NOT READY - ALL TESTS FAILED');
      console.log(`   ✗ ${failedTests.length} tests failed`);
    }

  } catch (error) {
    results.overallStatus = 'error';
    results.error = error.message;
    console.log('');
    console.log('💥 SYSTEM TEST FAILED:', error.message);
  }

  console.log('');
  console.log('📊 Test Summary:');
  Object.entries(results.tests).forEach(([testName, testResult]) => {
    const status = testResult.status === 'passed' ? '✓' : '✗';
    console.log(`   ${status} ${testName}: ${testResult.message}`);
  });

  return results;
}

/**
 * Get a simple status message
 * @param {Object} results - Test results
 * @returns {string} Status message
 */
export function getStatusMessage(results) {
  switch (results.overallStatus) {
    case 'ready':
      return '✅ System is ready for crash reporting';
    case 'partial':
      return '⚠️  System has issues but may work partially';
    case 'failed':
      return '❌ System is not ready for crash reporting';
    case 'error':
      return '💥 System test failed';
    default:
      return '❓ System status unknown';
  }
}

// Run test if called directly
if (import.meta.url === `file://${process.argv[1]}`) {
  quickSystemTest()
    .then(results => {
      console.log('');
      console.log(getStatusMessage(results));
      process.exit(results.overallStatus === 'ready' ? 0 : 1);
    })
    .catch(error => {
      console.error('Test failed:', error);
      process.exit(1);
    });
} 