/**
 * Rageshake Configuration
 *
 * This file contains configuration settings for the Rageshake crash reporting system.
 */

export const RAGESHAKE_CONFIG = {
  // Server configuration
  SERVER: {
    // Base URL for Rageshake server
    BASE_URL: 'https://logs.privateline.io',
    // Upload endpoint for crash reports
    UPLOAD_ENDPOINT: '/api/submit',
    // Full upload URL
    UPLOAD_URL: 'https://logs.privateline.io/api/submit',
  },

  // File configuration
  FILES: {
    // Maximum size for individual log files (4MB)
    MAX_LOG_SIZE: 4 * 1024 * 1024,
    // Maximum size for crash dumps (5MB)
    MAX_CRASH_DUMP_SIZE: 5 * 1024 * 1024,
    // Maximum total report size (25MB)
    MAX_REPORT_SIZE: 25 * 1024 * 1024,
    // Maximum number of crash dumps to include
    MAX_CRASH_DUMPS: 5,
    // Maximum number of log files to include
    MAX_LOGS: 10,
  },

  // Application configuration
  APP: {
    // Product name for Rageshake
    PRODUCT_NAME: 'privateLINE Connect desktop',
    // Company name
    COMPANY_NAME: 'privateLINE',
    // Application identifier (matches rageshake config)
    APP_ID: 'privateline-connect-desktop',
    // Default label for crash reports
    DEFAULT_LABEL: 'crash-report',
    // Rate limiting (reports per hour)
    RATE_LIMIT: 10,
    // Whether to compress reports
    COMPRESS_REPORTS: true,
  },

  // Data collection configuration
  DATA: {
    // Include system information
    INCLUDE_SYSTEM_INFO: true,
    // Include network information
    INCLUDE_NETWORK_INFO: true,
    // Include process information
    INCLUDE_PROCESS_INFO: true,
    // Include memory information
    INCLUDE_MEMORY_INFO: true,
    // Include crash dumps
    INCLUDE_CRASH_DUMPS: true,
    // Include application logs
    INCLUDE_APP_LOGS: true,
  },

  // Privacy configuration
  PRIVACY: {
    // Anonymize user data
    ANONYMIZE_USER_DATA: true,
    // Remove sensitive information
    REMOVE_SENSITIVE_DATA: true,
    // Maximum log lines to include
    MAX_LOG_LINES: 1000,
  }
};

/**
 * Get the full upload URL for crash reports
 * @returns {string} The complete upload URL
 */
export function getUploadURL() {
  return RAGESHAKE_CONFIG.SERVER.UPLOAD_URL;
}

/**
 * Get server configuration
 * @returns {Object} Server configuration object
 */
export function getServerConfig() {
  return RAGESHAKE_CONFIG.SERVER;
}

/**
 * Get file management configuration
 * @returns {Object} File management configuration object
 */
export function getFileConfig() {
  return RAGESHAKE_CONFIG.FILES;
}

/**
 * Get application configuration
 * @returns {Object} Application configuration object
 */
export function getAppConfig() {
  return RAGESHAKE_CONFIG.APP;
}

/**
 * Get data collection configuration
 * @returns {Object} Data collection configuration object
 */
export function getDataConfig() {
  return RAGESHAKE_CONFIG.DATA;
}

/**
 * Get privacy configuration
 * @returns {Object} Privacy configuration object
 */
export function getPrivacyConfig() {
  return RAGESHAKE_CONFIG.PRIVACY;
}