/**
 * Rageshake API Client
 * 
 * This module handles the submission of crash reports to the Rageshake server
 * following the official Matrix Rageshake API specification.
 */

import { getUploadURL, getServerConfig, getAppConfig } from './config.js';

/**
 * Rageshake API client class
 */
export class RageshakeAPI {
  constructor() {
    this.serverUrl = getUploadURL();
    this.serverConfig = getServerConfig();
    this.appConfig = getAppConfig();
  }

  /**
   * Submit a crash report to the Rageshake server
   * @param {Object} report - The crash report object
   * @param {string} report.text - Textual description of the problem
   * @param {string} report.user_agent - Application user-agent
   * @param {string} report.app - Application identifier
   * @param {string} report.version - Application version
   * @param {string} report.label - Label for the report
   * @param {Array} report.logs - Array of log file objects
   * @param {Array} report.files - Array of file objects
   * @param {Object} report.metadata - Additional metadata
   * @returns {Promise<Object>} Response from the server
   */
  async submitReport(report) {
    try {
      console.log('Submitting crash report to Rageshake server:', this.serverUrl);

      // Prepare the form data according to official Rageshake API specification
      const formData = new FormData();

      // Required fields
      if (report.text) {
        formData.append('text', report.text);
      }

      if (report.user_agent) {
        formData.append('user_agent', report.user_agent);
      }

      if (report.app) {
        formData.append('app', report.app);
      }

      if (report.version) {
        formData.append('version', report.version);
      }

      if (report.label) {
        formData.append('label', report.label);
      }

      // Log files - each log as a separate 'log' field
      if (report.logs && Array.isArray(report.logs)) {
        report.logs.forEach((log, index) => {
          if (log.content && log.filename) {
            const blob = new Blob([log.content], { type: 'text/plain' });
            formData.append('log', blob, log.filename);
          }
        });
      }

      // Compressed log files - each as a separate 'compressed-log' field
      if (report.compressed_logs && Array.isArray(report.compressed_logs)) {
        report.compressed_logs.forEach((log, index) => {
          if (log.content && log.filename) {
            const blob = new Blob([log.content], { type: 'application/gzip' });
            formData.append('compressed-log', blob, log.filename);
          }
        });
      }

      // Additional files - each as a separate 'file' field
      if (report.files && Array.isArray(report.files)) {
        report.files.forEach((file, index) => {
          if (file.content && file.filename) {
            const blob = new Blob([file.content], { type: file.mimeType || 'application/octet-stream' });
            formData.append('file', blob, file.filename);
          }
        });
      }

      // Additional metadata - any other form fields
      if (report.metadata && typeof report.metadata === 'object') {
        Object.keys(report.metadata).forEach(key => {
          const value = report.metadata[key];
          if (value !== null && value !== undefined) {
            formData.append(key, String(value));
          }
        });
      }

      // Submit the report
      const response = await fetch(this.serverUrl, {
        method: 'POST',
        body: formData,
        headers: {
          'User-Agent': 'PrivateLINE-Connect-Rageshake/1.0'
        }
      });

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`Rageshake submission failed: ${response.status} ${response.statusText} - ${errorText}`);
      }

      const result = await response.json();
      console.log('Rageshake submission successful:', result);

      return {
        success: true,
        status: response.status,
        response: result,
        reportUrl: result.report_url || null
      };

    } catch (error) {
      console.error('Rageshake submission error:', error);
      throw error;
    }
  }

  /**
   * Test the Rageshake server connection
   * @returns {Promise<Object>} Connection test result
   */
  async testConnection() {
    try {
      console.log('Testing Rageshake server connection:', this.serverUrl);

      // Test with a simple HEAD request
      const response = await fetch(this.serverUrl, {
        method: 'HEAD',
        headers: {
          'User-Agent': 'PrivateLINE-Connect-Rageshake-Test/1.0'
        }
      });

      return {
        success: response.ok,
        status: response.status,
        statusText: response.statusText,
        serverUrl: this.serverUrl,
        timestamp: new Date().toISOString()
      };

    } catch (error) {
      console.error('Rageshake connection test failed:', error);
      return {
        success: false,
        error: error.message,
        serverUrl: this.serverUrl,
        timestamp: new Date().toISOString()
      };
    }
  }

  /**
   * Test with a sample crash report payload
   * @returns {Promise<Object>} Test submission result
   */
  async testSubmission() {
    const testReport = {
      text: 'This is a test crash report from PrivateLINE Connect',
      user_agent: 'PrivateLINE-Connect-Test/1.0',
      app: this.appConfig.APP_ID,
      version: '1.0.0',
      label: this.appConfig.DEFAULT_LABEL,
      logs: [
        {
          filename: 'test-app.log',
          content: `Test log file content
Timestamp: ${new Date().toISOString()}
Platform: ${process.platform}
Version: 1.0.0`
        }
      ],
      metadata: {
        test: 'true',
        timestamp: new Date().toISOString(),
        platform: process.platform,
        client_version: '1.0.0'
      }
    };

    try {
      return await this.submitReport(testReport);
    } catch (error) {
      return {
        success: false,
        error: error.message,
        testReport
      };
    }
  }

  /**
   * Create a crash report from collected data
   * @param {Object} crashData - Collected crash data
   * @param {string} crashType - Type of crash
   * @param {string} userDescription - User's description
   * @returns {Object} Formatted crash report
   */
  createCrashReport(crashData, crashType, userDescription = '') {
    const report = {
      text: userDescription || `Crash Report: ${crashType}`,
      user_agent: `PrivateLINE-Connect/${crashData.system?.appVersion || '1.0.0'} (${process.platform})`,
      app: this.appConfig.APP_ID,
      version: crashData.system?.appVersion || '1.0.0',
      label: this.appConfig.DEFAULT_LABEL,
      logs: [],
      files: [],
      metadata: {
        crash_type: crashType,
        timestamp: new Date().toISOString(),
        platform: crashData.system?.platform || process.platform,
        architecture: crashData.system?.arch || process.arch,
        electron_version: crashData.system?.electronVersion || '',
        chrome_version: crashData.system?.chromeVersion || '',
        node_version: crashData.system?.nodeVersion || process.version
      }
    };

    // Add system information as a log
    if (crashData.system) {
      report.logs.push({
        filename: 'system-info.log',
        content: JSON.stringify(crashData.system, null, 2)
      });
    }

    // Add crash dumps as files
    if (crashData.crashDumps && Array.isArray(crashData.crashDumps)) {
      crashData.crashDumps.forEach((dump, index) => {
        if (dump.content) {
          report.files.push({
            filename: `crash-dump-${index + 1}.dmp`,
            content: dump.content,
            mimeType: 'application/octet-stream'
          });
        }
      });
    }

    // Add log files
    if (crashData.logs && Array.isArray(crashData.logs)) {
      crashData.logs.forEach((log, index) => {
        if (log.content) {
          report.logs.push({
            filename: `log-${index + 1}.log`,
            content: log.content
          });
        }
      });
    }

    // Add additional data as metadata
    if (crashData.additionalData && typeof crashData.additionalData === 'object') {
      Object.keys(crashData.additionalData).forEach(key => {
        const value = crashData.additionalData[key];
        if (value !== null && value !== undefined) {
          report.metadata[key] = String(value);
        }
      });
    }

    return report;
  }
}

/**
 * Create a Rageshake API client instance
 * @returns {RageshakeAPI} API client instance
 */
export function createRageshakeAPI() {
  return new RageshakeAPI();
}

/**
 * Submit a crash report using the standard Rageshake format
 * @param {Object} reportData - Crash report data
 * @returns {Promise<Object>} Submission result
 */
export async function submitCrashReport(reportData) {
  const api = createRageshakeAPI();
  return await api.submitReport(reportData);
}

/**
 * Test Rageshake server connectivity
 * @returns {Promise<Object>} Test result
 */
export async function testRageshakeServer() {
  const api = createRageshakeAPI();
  return await api.testConnection();
} 