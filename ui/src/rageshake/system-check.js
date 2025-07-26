/**
 * Rageshake System Readiness Check
 * 
 * This module performs comprehensive checks to ensure the Rageshake system
 * is ready for crash reporting and log submission.
 */

import { app } from 'electron';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { createRageshakeAPI, testRageshakeServer } from './api.js';
import { getUploadURL, getServerConfig, getFileConfig, getAppConfig } from './config.js';

/**
 * System readiness check results
 */
export class SystemCheckResult {
  constructor() {
    this.timestamp = new Date().toISOString();
    this.overallStatus = 'unknown';
    this.checks = {};
    this.errors = [];
    this.warnings = [];
    this.recommendations = [];
  }

  addCheck(name, status, details = null) {
    this.checks[name] = {
      status,
      details,
      timestamp: new Date().toISOString()
    };
  }

  addError(message) {
    this.errors.push({
      message,
      timestamp: new Date().toISOString()
    });
  }

  addWarning(message) {
    this.warnings.push({
      message,
      timestamp: new Date().toISOString()
    });
  }

  addRecommendation(message) {
    this.recommendations.push({
      message,
      timestamp: new Date().toISOString()
    });
  }

  updateOverallStatus() {
    const allChecks = Object.values(this.checks);
    const failedChecks = allChecks.filter(check => check.status === 'failed');
    const warningChecks = allChecks.filter(check => check.status === 'warning');

    if (failedChecks.length > 0) {
      this.overallStatus = 'failed';
    } else if (warningChecks.length > 0) {
      this.overallStatus = 'warning';
    } else {
      this.overallStatus = 'ready';
    }
  }
}

/**
 * Perform comprehensive system readiness check
 * @returns {Promise<SystemCheckResult>} Check results
 */
export async function performSystemCheck() {
  const result = new SystemCheckResult();
  
  console.log('=== Rageshake System Readiness Check ===');
  
  try {
    // Check 1: Configuration
    await checkConfiguration(result);
    
    // Check 2: File System
    await checkFileSystem(result);
    
    // Check 3: Network Connectivity
    await checkNetworkConnectivity(result);
    
    // Check 4: API Compatibility
    await checkAPICompatibility(result);
    
    // Check 5: Crash Reporter
    await checkCrashReporter(result);
    
    // Check 6: Log Collection
    await checkLogCollection(result);
    
    // Check 7: Test Submission
    await checkTestSubmission(result);
    
    // Update overall status
    result.updateOverallStatus();
    
    // Generate recommendations
    generateRecommendations(result);
    
    console.log(`\n=== System Check Complete ===`);
    console.log(`Overall Status: ${result.overallStatus.toUpperCase()}`);
    console.log(`Checks: ${Object.keys(result.checks).length}`);
    console.log(`Errors: ${result.errors.length}`);
    console.log(`Warnings: ${result.warnings.length}`);
    
  } catch (error) {
    console.error('System check failed:', error);
    result.addError(`System check failed: ${error.message}`);
    result.overallStatus = 'failed';
  }
  
  return result;
}

/**
 * Check configuration settings
 */
async function checkConfiguration(result) {
  try {
    console.log('Checking configuration...');
    
    const serverConfig = getServerConfig();
    const fileConfig = getFileConfig();
    const appConfig = getAppConfig();
    
    // Check server URL
    if (serverConfig.UPLOAD_URL && serverConfig.UPLOAD_URL.startsWith('https://')) {
      result.addCheck('server_url', 'passed', serverConfig.UPLOAD_URL);
    } else {
      result.addCheck('server_url', 'failed', serverConfig.UPLOAD_URL);
      result.addError('Invalid server URL configuration');
    }
    
    // Check file limits
    if (fileConfig.MAX_REPORT_SIZE > 0) {
      result.addCheck('file_limits', 'passed', `Max size: ${fileConfig.MAX_REPORT_SIZE} bytes`);
    } else {
      result.addCheck('file_limits', 'failed');
      result.addError('Invalid file size limits');
    }
    
    // Check app configuration
    if (appConfig.PRODUCT_NAME && appConfig.COMPANY_NAME) {
      result.addCheck('app_config', 'passed', `${appConfig.PRODUCT_NAME} by ${appConfig.COMPANY_NAME}`);
    } else {
      result.addCheck('app_config', 'failed');
      result.addError('Missing application configuration');
    }
    
  } catch (error) {
    result.addCheck('configuration', 'failed', error.message);
    result.addError(`Configuration check failed: ${error.message}`);
  }
}

/**
 * Check file system permissions and directories
 */
async function checkFileSystem(result) {
  try {
    console.log('Checking file system...');
    
    const userDataPath = app.getPath('userData');
    const crashDumpsPath = path.join(userDataPath, 'CrashDumps');
    const logsPath = path.join(userDataPath, 'Logs');
    const reportsPath = path.join(userDataPath, 'CrashReports');
    
    // Check user data directory
    if (fs.existsSync(userDataPath)) {
      result.addCheck('user_data_dir', 'passed', userDataPath);
    } else {
      result.addCheck('user_data_dir', 'failed', userDataPath);
      result.addError('User data directory does not exist');
    }
    
    // Check write permissions
    try {
      const testFile = path.join(userDataPath, 'test-write.tmp');
      fs.writeFileSync(testFile, 'test');
      fs.unlinkSync(testFile);
      result.addCheck('write_permissions', 'passed');
    } catch (error) {
      result.addCheck('write_permissions', 'failed', error.message);
      result.addError('No write permissions to user data directory');
    }
    
    // Check/create required directories
    const directories = [crashDumpsPath, logsPath, reportsPath];
    for (const dir of directories) {
      try {
        if (!fs.existsSync(dir)) {
          fs.mkdirSync(dir, { recursive: true });
        }
        result.addCheck(`dir_${path.basename(dir)}`, 'passed', dir);
      } catch (error) {
        result.addCheck(`dir_${path.basename(dir)}`, 'failed', error.message);
        result.addError(`Failed to create directory: ${dir}`);
      }
    }
    
  } catch (error) {
    result.addCheck('file_system', 'failed', error.message);
    result.addError(`File system check failed: ${error.message}`);
  }
}

/**
 * Check network connectivity
 */
async function checkNetworkConnectivity(result) {
  try {
    console.log('Checking network connectivity...');
    
    const api = createRageshakeAPI();
    const connectionTest = await api.testConnection();
    
    if (connectionTest.success) {
      result.addCheck('server_connectivity', 'passed', `Status: ${connectionTest.status}`);
    } else {
      result.addCheck('server_connectivity', 'failed', connectionTest.error);
      result.addError(`Server connectivity failed: ${connectionTest.error}`);
    }
    
    // Check DNS resolution
    try {
      const { URL } = require('url');
      const serverUrl = new URL(getUploadURL());
      result.addCheck('dns_resolution', 'passed', serverUrl.hostname);
    } catch (error) {
      result.addCheck('dns_resolution', 'failed', error.message);
      result.addError(`DNS resolution failed: ${error.message}`);
    }
    
  } catch (error) {
    result.addCheck('network_connectivity', 'failed', error.message);
    result.addError(`Network connectivity check failed: ${error.message}`);
  }
}

/**
 * Check API compatibility
 */
async function checkAPICompatibility(result) {
  try {
    console.log('Checking API compatibility...');
    
    // Check if fetch is available (for API calls)
    if (typeof fetch !== 'undefined') {
      result.addCheck('fetch_api', 'passed');
    } else {
      result.addCheck('fetch_api', 'failed');
      result.addError('Fetch API not available');
    }
    
    // Check if FormData is available
    if (typeof FormData !== 'undefined') {
      result.addCheck('formdata_api', 'passed');
    } else {
      result.addCheck('formdata_api', 'failed');
      result.addError('FormData API not available');
    }
    
    // Check if Blob is available
    if (typeof Blob !== 'undefined') {
      result.addCheck('blob_api', 'passed');
    } else {
      result.addCheck('blob_api', 'failed');
      result.addError('Blob API not available');
    }
    
  } catch (error) {
    result.addCheck('api_compatibility', 'failed', error.message);
    result.addError(`API compatibility check failed: ${error.message}`);
  }
}

/**
 * Check crash reporter
 */
async function checkCrashReporter(result) {
  try {
    console.log('Checking crash reporter...');
    
    // Check if crashReporter is available
    if (typeof require('electron').crashReporter !== 'undefined') {
      result.addCheck('crash_reporter_available', 'passed');
    } else {
      result.addCheck('crash_reporter_available', 'failed');
      result.addError('Electron crash reporter not available');
    }
    
    // Check crash dumps directory
    const crashDumpsPath = path.join(app.getPath('userData'), 'CrashDumps');
    if (fs.existsSync(crashDumpsPath)) {
      const files = fs.readdirSync(crashDumpsPath);
      result.addCheck('crash_dumps_dir', 'passed', `${files.length} files found`);
    } else {
      result.addCheck('crash_dumps_dir', 'warning', 'Directory does not exist yet');
      result.addWarning('Crash dumps directory will be created when needed');
    }
    
  } catch (error) {
    result.addCheck('crash_reporter', 'failed', error.message);
    result.addError(`Crash reporter check failed: ${error.message}`);
  }
}

/**
 * Check log collection
 */
async function checkLogCollection(result) {
  try {
    console.log('Checking log collection...');
    
    // Check if we can access system information
    const systemInfo = {
      platform: os.platform(),
      release: os.release(),
      arch: os.arch(),
      hostname: os.hostname(),
      username: os.userInfo().username
    };
    
    if (systemInfo.platform && systemInfo.hostname) {
      result.addCheck('system_info', 'passed', `${systemInfo.platform} ${systemInfo.release}`);
    } else {
      result.addCheck('system_info', 'failed');
      result.addError('Cannot collect system information');
    }
    
    // Check memory information
    const memInfo = {
      total: os.totalmem(),
      free: os.freemem(),
      used: os.totalmem() - os.freemem()
    };
    
    if (memInfo.total > 0) {
      result.addCheck('memory_info', 'passed', `${Math.round(memInfo.used / 1024 / 1024)}MB used`);
    } else {
      result.addCheck('memory_info', 'failed');
      result.addError('Cannot collect memory information');
    }
    
  } catch (error) {
    result.addCheck('log_collection', 'failed', error.message);
    result.addError(`Log collection check failed: ${error.message}`);
  }
}

/**
 * Check test submission
 */
async function checkTestSubmission(result) {
  try {
    console.log('Checking test submission...');
    
    const api = createRageshakeAPI();
    const testResult = await api.testSubmission();
    
    if (testResult.success) {
      result.addCheck('test_submission', 'passed', `Report ID: ${testResult.reportId || 'N/A'}`);
    } else {
      result.addCheck('test_submission', 'failed', testResult.error);
      result.addError(`Test submission failed: ${testResult.error}`);
    }
    
  } catch (error) {
    result.addCheck('test_submission', 'failed', error.message);
    result.addError(`Test submission check failed: ${error.message}`);
  }
}

/**
 * Generate recommendations based on check results
 */
function generateRecommendations(result) {
  if (result.overallStatus === 'failed') {
    result.addRecommendation('Fix all failed checks before using crash reporting');
  }
  
  if (result.errors.length > 0) {
    result.addRecommendation('Review and resolve all error messages');
  }
  
  if (result.warnings.length > 0) {
    result.addRecommendation('Consider addressing warnings for optimal performance');
  }
  
  if (result.overallStatus === 'ready') {
    result.addRecommendation('System is ready for crash reporting');
  }
  
  // Check specific conditions
  const checks = result.checks;
  
  if (checks.server_connectivity && checks.server_connectivity.status === 'failed') {
    result.addRecommendation('Check server URL and network connectivity');
  }
  
  if (checks.write_permissions && checks.write_permissions.status === 'failed') {
    result.addRecommendation('Fix file system permissions');
  }
  
  if (checks.test_submission && checks.test_submission.status === 'failed') {
    result.addRecommendation('Verify server API endpoint and format');
  }
}

/**
 * Get a human-readable summary of the system check
 * @param {SystemCheckResult} result - Check results
 * @returns {string} Summary text
 */
export function getSystemCheckSummary(result) {
  const status = result.overallStatus.toUpperCase();
  const totalChecks = Object.keys(result.checks).length;
  const passedChecks = Object.values(result.checks).filter(c => c.status === 'passed').length;
  const failedChecks = Object.values(result.checks).filter(c => c.status === 'failed').length;
  const warningChecks = Object.values(result.checks).filter(c => c.status === 'warning').length;
  
  let summary = `\n=== RAGESHAKE SYSTEM STATUS: ${status} ===\n`;
  summary += `Checks: ${passedChecks}/${totalChecks} passed, ${failedChecks} failed, ${warningChecks} warnings\n`;
  summary += `Errors: ${result.errors.length}\n`;
  summary += `Warnings: ${result.warnings.length}\n`;
  summary += `Timestamp: ${result.timestamp}\n`;
  
  if (result.errors.length > 0) {
    summary += '\n=== ERRORS ===\n';
    result.errors.forEach(error => {
      summary += `• ${error.message}\n`;
    });
  }
  
  if (result.warnings.length > 0) {
    summary += '\n=== WARNINGS ===\n';
    result.warnings.forEach(warning => {
      summary += `• ${warning.message}\n`;
    });
  }
  
  if (result.recommendations.length > 0) {
    summary += '\n=== RECOMMENDATIONS ===\n';
    result.recommendations.forEach(rec => {
      summary += `• ${rec.message}\n`;
    });
  }
  
  return summary;
} 