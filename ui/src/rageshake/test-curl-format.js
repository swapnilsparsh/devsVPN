/**
 * Test Rageshake API with curl-compatible format
 * 
 * This script tests the Rageshake API using the same format as the user's curl request:
 * curl --location 'https://logs.privateline.io/api/submit' \
 * --form 'upload_file_min_type=@"/C:/Users/sandeep/AppData/Roaming/privateline-connect-ui/CrashReports/crash-report-2025-07-26T08-14-51-768Z.json"' \
 * --form 'metadata="{\"client_version\":\"1.0.0\",\"platform\":\"linux_sandeep\"}"'
 */

import { getUploadURL } from './config.js';

/**
 * Test Rageshake API with curl-compatible format
 * @returns {Promise<Object>} Test results
 */
export async function testCurlFormat() {
  const results = {
    timestamp: new Date().toISOString(),
    serverUrl: getUploadURL(),
    tests: {},
    overallStatus: 'unknown'
  };

  console.log('🔍 Testing Rageshake API with curl-compatible format');
  console.log(`📡 Server URL: ${results.serverUrl}`);
  console.log('');

  try {
    // Test 1: Basic connectivity
    console.log('✅ Testing basic connectivity...');
    try {
      const response = await fetch(results.serverUrl, {
        method: 'HEAD',
        headers: {
          'User-Agent': 'PrivateLINE-Connect-Test/1.0'
        }
      });
      
      if (response.ok) {
        results.tests.connectivity = { 
          status: 'passed', 
          message: `Server accessible (${response.status})` 
        };
        console.log(`   ✓ Server accessible (${response.status})`);
      } else {
        results.tests.connectivity = { 
          status: 'failed', 
          message: `Server returned ${response.status}` 
        };
        console.log(`   ✗ Server returned ${response.status}`);
      }
    } catch (error) {
      results.tests.connectivity = { status: 'failed', message: error.message };
      console.log('   ✗ Connectivity failed:', error.message);
    }

    // Test 2: Curl-compatible format test
    console.log('📤 Testing curl-compatible format...');
    try {
      // Create test data similar to the curl request
      const testMetadata = {
        client_version: '1.0.0',
        platform: 'linux_sandeep',
        test: 'true',
        timestamp: new Date().toISOString()
      };

      const testFileContent = JSON.stringify({
        crash_type: 'test',
        timestamp: new Date().toISOString(),
        platform: 'linux_sandeep',
        client_version: '1.0.0',
        test_data: 'This is a test crash report file'
      }, null, 2);

      // Create form data matching curl format
      const formData = new FormData();
      
      // Add file (similar to upload_file_min_type in curl)
      const testFile = new Blob([testFileContent], { type: 'application/json' });
      formData.append('upload_file_min_type', testFile, 'test-crash-report.json');
      
      // Add metadata (similar to metadata in curl)
      formData.append('metadata', JSON.stringify(testMetadata));

      // Submit the test
      const response = await fetch(results.serverUrl, {
        method: 'POST',
        body: formData,
        headers: {
          'User-Agent': 'PrivateLINE-Connect-Test/1.0'
        }
      });

      if (response.ok) {
        const responseData = await response.json();
        results.tests.curl_format = { 
          status: 'passed', 
          message: `Test submission successful${responseData.report_url ? ` (URL: ${responseData.report_url})` : ''}` 
        };
        console.log(`   ✓ Test submission successful${responseData.report_url ? ` (URL: ${responseData.report_url})` : ''}`);
      } else {
        const errorText = await response.text();
        results.tests.curl_format = { 
          status: 'failed', 
          message: `Server returned ${response.status}: ${errorText}` 
        };
        console.log(`   ✗ Test submission failed: ${response.status} - ${errorText}`);
      }
    } catch (error) {
      results.tests.curl_format = { status: 'failed', message: error.message };
      console.log('   ✗ Curl format test failed:', error.message);
    }

    // Test 3: Official Rageshake format test
    console.log('📋 Testing official Rageshake format...');
    try {
      const formData = new FormData();
      
      // Required fields
      formData.append('text', 'Test crash report from PrivateLINE Connect');
      formData.append('user_agent', 'PrivateLINE-Connect-Test/1.0');
      formData.append('app', 'privateline-connect');
      formData.append('version', '1.0.0');
      formData.append('label', 'test-crash');
      
      // Log file
      const logContent = `Test log content
Timestamp: ${new Date().toISOString()}
Platform: linux_sandeep
Version: 1.0.0`;
      const logFile = new Blob([logContent], { type: 'text/plain' });
      formData.append('log', logFile, 'test-app.log');
      
      // Additional metadata
      formData.append('client_version', '1.0.0');
      formData.append('platform', 'linux_sandeep');
      formData.append('test', 'true');

      const response = await fetch(results.serverUrl, {
        method: 'POST',
        body: formData,
        headers: {
          'User-Agent': 'PrivateLINE-Connect-Test/1.0'
        }
      });

      if (response.ok) {
        const responseData = await response.json();
        results.tests.official_format = { 
          status: 'passed', 
          message: `Official format successful${responseData.report_url ? ` (URL: ${responseData.report_url})` : ''}` 
        };
        console.log(`   ✓ Official format successful${responseData.report_url ? ` (URL: ${responseData.report_url})` : ''}`);
      } else {
        const errorText = await response.text();
        results.tests.official_format = { 
          status: 'failed', 
          message: `Server returned ${response.status}: ${errorText}` 
        };
        console.log(`   ✗ Official format failed: ${response.status} - ${errorText}`);
      }
    } catch (error) {
      results.tests.official_format = { status: 'failed', message: error.message };
      console.log('   ✗ Official format test failed:', error.message);
    }

    // Determine overall status
    const failedTests = Object.values(results.tests).filter(test => test.status === 'failed');
    const passedTests = Object.values(results.tests).filter(test => test.status === 'passed');

    if (failedTests.length === 0) {
      results.overallStatus = 'ready';
      console.log('');
      console.log('🎉 ALL TESTS PASSED - SYSTEM IS READY!');
      console.log(`   ✓ All ${passedTests.length} tests passed`);
    } else if (passedTests.length > 0) {
      results.overallStatus = 'partial';
      console.log('');
      console.log('⚠️  PARTIAL SUCCESS - SOME TESTS FAILED');
      console.log(`   ✓ ${passedTests.length} tests passed`);
      console.log(`   ✗ ${failedTests.length} tests failed`);
    } else {
      results.overallStatus = 'failed';
      console.log('');
      console.log('❌ ALL TESTS FAILED - SYSTEM NOT READY');
      console.log(`   ✗ ${failedTests.length} tests failed`);
    }

  } catch (error) {
    results.overallStatus = 'error';
    results.error = error.message;
    console.log('');
    console.log('💥 TEST FAILED:', error.message);
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
 * Get compatibility status
 * @param {Object} results - Test results
 * @returns {string} Compatibility status
 */
export function getCompatibilityStatus(results) {
  const tests = results.tests;
  
  if (tests.curl_format && tests.curl_format.status === 'passed') {
    return '✅ FULLY COMPATIBLE - Both curl and official formats work';
  } else if (tests.official_format && tests.official_format.status === 'passed') {
    return '⚠️  PARTIALLY COMPATIBLE - Official format works, curl format needs adjustment';
  } else if (tests.connectivity && tests.connectivity.status === 'passed') {
    return '🔧 SERVER ACCESSIBLE - API format needs configuration';
  } else {
    return '❌ NOT COMPATIBLE - Server connectivity issues';
  }
}

// Run test if called directly
if (import.meta.url === `file://${process.argv[1]}`) {
  testCurlFormat()
    .then(results => {
      console.log('');
      console.log(getCompatibilityStatus(results));
      process.exit(results.overallStatus === 'ready' ? 0 : 1);
    })
    .catch(error => {
      console.error('Test failed:', error);
      process.exit(1);
    });
} 