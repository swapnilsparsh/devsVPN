import { app, crashReporter, dialog } from 'electron';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { SentrySendDiagnosticReport } from '../sentry/sentry.js';
import { RAGESHAKE_CONFIG, getUploadURL, getAppConfig, getFileConfig } from './config.js';
import { createRageshakeAPI, submitCrashReport } from './api.js';

import daemonClient from "@/daemon-client";
class Rageshake {
  constructor() {
    this.isEnabled = false;
    this.crashDumpsPath = null;
    this.logsPath = null;
    this.maxCrashDumps = getFileConfig().MAX_CRASH_DUMPS;
    this.maxLogs = getFileConfig().MAX_LOGS;
  }

  /**
   * Initialize Rageshake crash reporting
   */
  init() {
    try {
      // Set up crash reporter
      this.setupCrashReporter();

      // Set up paths
      this.setupPaths();

      // Enable crash reporting
      this.isEnabled = true;

      console.log('Rageshake crash reporting initialized');
    } catch (error) {
      console.error('Failed to initialize Rageshake:', error);
    }
  }

  /**
   * Set up Electron crash reporter
   */
  setupCrashReporter() {
    const uploadURL = getUploadURL();
    const appConfig = getAppConfig();

    crashReporter.start({
      productName: appConfig.PRODUCT_NAME,
      companyName: appConfig.COMPANY_NAME,
      submitURL: uploadURL,
      uploadToServer: false, // We'll handle upload manually
      ignoreSystemCrashHandler: false,
      rateLimit: appConfig.RATE_LIMIT,
      maxUploadSize: getFileConfig().MAX_REPORT_SIZE,
      compress: appConfig.COMPRESS_REPORTS,
      extra: {
        version: app.getVersion(),
        platform: process.platform,
        arch: process.arch,
        electronVersion: process.versions.electron,
        chromeVersion: process.versions.chrome,
        nodeVersion: process.versions.node
      }
    });
  }

  /**
   * Set up paths for crash dumps and logs
   */
  setupPaths() {
    const userDataPath = app.getPath('userData');
    this.crashDumpsPath = path.join(userDataPath, 'CrashDumps');
    this.logsPath = path.join(userDataPath, 'logs');

    // Create directories if they don't exist
    this.ensureDirectoryExists(this.crashDumpsPath);
    this.ensureDirectoryExists(this.logsPath);
  }

  /**
   * Ensure directory exists
   */
  ensureDirectoryExists(dirPath) {
    if (!fs.existsSync(dirPath)) {
      fs.mkdirSync(dirPath, { recursive: true });
    }
  }

  /**
   * Collect crash report data
   */
  async collectCrashReport(crashType = 'ui - manual', errMsg, additionalData = {}) {
    const report = {
      crashType,
      timestamp: new Date().toISOString(),
      userDescription: errMsg || additionalData.userDescription || '',
      systemInfo: await this.collectSystemInfo(),
      crashDumps: await this.collectCrashDumps(),
      logs: await this.collectLogs(),
      additionalData
    };

    // // Add content to crash dumps
    // report.crashDumps = report.crashDumps.map(dump => ({
    //   ...dump,
    //   content: this.readFileSafely(dump.path, getFileConfig().MAX_CRASH_DUMP_SIZE)
    // }));

    // // Add content to logs
    // report.logs = report.logs.map(log => ({
    //   ...log,
    //   content: this.readFileSafely(log.path, getFileConfig().MAX_LOG_SIZE)
    // }));

    return report;
  }

  /**
   * Collect system information
   */
  collectSystemInfo() {
    return {
      platform: process.platform,
      arch: process.arch,
      version: process.version,
      electronVersion: process.versions.electron,
      chromeVersion: process.versions.chrome,
      nodeVersion: process.versions.node,
      appVersion: app.getVersion(),
      osInfo: {
        platform: os.platform(),
        release: os.release(),
        arch: os.arch(),
        cpus: os.cpus().length,
        totalMemory: os.totalmem(),
        freeMemory: os.freemem(),
        uptime: os.uptime()
      },
      userInfo: {
        username: os.userInfo().username,
        homedir: os.userInfo().homedir
      }
    };
  }

  /**
   * Collect crash dump files
   */
  async collectCrashDumps() {
    try {
      if (!fs.existsSync(this.crashDumpsPath)) {
        return [];
      }

      const files = fs.readdirSync(this.crashDumpsPath);
      const crashFiles = files
        .filter(file => file.endsWith('.dmp'))
        .sort((a, b) => {
          const statA = fs.statSync(path.join(this.crashDumpsPath, a));
          const statB = fs.statSync(path.join(this.crashDumpsPath, b));
          return statB.mtime.getTime() - statA.mtime.getTime();
        })
        .slice(0, this.maxCrashDumps);


      return crashFiles.map(file => path.join(this.crashDumpsPath, file)); // return only paths to files, daemon will package them

      // return crashFiles.map(file => ({
      //   name: file,
      //   path: path.join(this.crashDumpsPath, file),
      //   size: fs.statSync(path.join(this.crashDumpsPath, file)).size
      // }));
    } catch (error) {
      console.error('Error collecting crash dumps:', error);
      return [];
    }
  }

  /**
   * Collect log files
   */
  async collectLogs() {
    try {
      if (!fs.existsSync(this.logsPath)) {
        return [];
      }

      const files = fs.readdirSync(this.logsPath);
      const logFiles = files
        .filter(file => file.endsWith('.log'))
        .sort((a, b) => {
          const statA = fs.statSync(path.join(this.logsPath, a));
          const statB = fs.statSync(path.join(this.logsPath, b));
          return statB.mtime.getTime() - statA.mtime.getTime();
        })
        .slice(0, this.maxLogs);

      return logFiles.map(file => path.join(this.logsPath, file)); // return only paths to files, daemon will package them

      // return logFiles.map(file => ({
      //   name: file,
      //   path: path.join(this.logsPath, file),
      //   size: fs.statSync(path.join(this.logsPath, file)).size
      // }));
    } catch (error) {
      console.error('Error collecting logs:', error);
      return [];
    }
  }

  /**
   * Read file content safely
   */
  readFileSafely(filePath, maxSize = getFileConfig().MAX_LOG_SIZE) {
    try {
      const stats = fs.statSync(filePath);
      if (stats.size > maxSize) {
        return `[File too large: ${stats.size} bytes, max: ${maxSize} bytes]`;
      }
      return fs.readFileSync(filePath, 'utf8');
    } catch (error) {
      return `[Error reading file: ${error.message}]`;
    }
  }

  /**
   * Generate crash report and show dialog
   */
  async showCrashReportDialog(crashType = 'ui - manual', userDescription, additionalData = {}) {
    try {
      const report = await this.collectCrashReport(crashType, userDescription, additionalData);
      let attachedFilesPaths = [];
      if (report.logs !== null && report.logs !== undefined)
          attachedFilesPaths.push(...report.logs);
      if (report.crashDumps !== null && report.crashDumps !== undefined)
          attachedFilesPaths.push(...report.crashDumps);

      const result = await dialog.showMessageBox({
        type: 'info',
        title: 'Problem Report Generated',
        message: `A problem report has been generated with PL Connect logs and system information, to be submitted to privateLINE tech support`,
        //detail: `Report contains:\n- System information\n- ${report.crashDumps.length} crash dumps\n- ${report.logs.length} log files\n- Additional data`,
        detail: `Problem description:\n\n${userDescription}`,
        buttons: ['Send Report', /*'Save Locally',*/ 'Cancel'],
        defaultId: 0,
        cancelId: 1
      });

      let resp = '';
      switch (result.response) {
        case 0: // Send Report
          resp = await daemonClient.SubmitRageshakeReport(crashType, report.userDescription, attachedFilesPaths, report.systemInfo, additionalData);
          break;
        // case 1: // Save Locally
        //   await this.saveCrashReportLocally(report);
        //   break;
        case 1: // Cancel
          return;
      }

      dialog.showMessageBoxSync({
        type: "info",
        buttons: ["OK"],
        message: "Problem report sent to privateLINE",
        detail: `It can be retrieved at this URL:\n\n${resp.report_url}`,
      });
    } catch (error) {
      console.error('Error showing crash report dialog:', error);
      dialog.showErrorBox('Error', `Failed to submit problem report:\n\n${error}`);
    }
  }

  /**
   * Send crash report via Rageshake API
   */
  // async sendCrashReport(report) {
  //   try {
  //     // Convert report to Rageshake API format using the API client
  //     const api = createRageshakeAPI();
  //     const rageshakeData = api.createCrashReport(report, report.crashType, report.userDescription);

  //     // Send via Rageshake API
  //     const result = await api.submitReport(rageshakeData);

  //     if (result.success) {
  //       dialog.showMessageBox({
  //         type: 'info',
  //         title: 'Report Sent',
  //         message: 'Crash report has been sent successfully.',
  //         detail: result.reportUrl ? `Report URL: ${result.reportUrl}` : 'Report submitted to Rageshake server'
  //       });
  //     } else {
  //       throw new Error('Failed to send report');
  //     }
  //   } catch (error) {
  //     console.error('Error sending crash report:', error);
  //     dialog.showErrorBox('Error', `Failed to send crash report: ${error.message}`);
  //   }
  // }

  /**
   * Convert crash report to Sentry format
   */
  convertToSentryFormat(report) {
    const sentryData = {};

    // System information
    sentryData['System Info'] = JSON.stringify(report.system, null, 2);

    // Crash dumps info
    if (report.crashDumps.length > 0) {
      sentryData['Crash Dumps'] = report.crashDumps.map(dump =>
        `${dump.name} (${dump.size} bytes)`
      ).join('\n');
    }

    // Log files content
    report.logs.forEach(log => {
      const content = this.readFileSafely(log.path, 4 * 1024 * 1024); // 4MB per log
      sentryData[`Log: ${log.name}`] = content;
    });

    // Additional data
    if (Object.keys(report.additionalData).length > 0) {
      sentryData['Additional Data'] = JSON.stringify(report.additionalData, null, 2);
    }

    return sentryData;
  }



  /**
   * Save crash report locally
   */
  async saveCrashReportLocally(report) {
    try {
      const userDataPath = app.getPath('userData');
      const reportsPath = path.join(userDataPath, 'CrashReports');
      this.ensureDirectoryExists(reportsPath);

      const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
      const filename = `crash-report-${timestamp}.json`;
      const filepath = path.join(reportsPath, filename);

      fs.writeFileSync(filepath, JSON.stringify(report, null, 2));

      dialog.showMessageBox({
        type: 'info',
        title: 'Report Saved',
        message: 'Crash report has been saved locally.',
        detail: `Location: ${filepath}`
      });
    } catch (error) {
      console.error('Error saving crash report:', error);
      dialog.showErrorBox('Error', `Failed to save crash report: ${error.message}`);
    }
  }

  /**
   * Clean up old crash dumps and logs
   */
  cleanup() {
    try {
      this.cleanupDirectory(this.crashDumpsPath, this.maxCrashDumps);
      this.cleanupDirectory(this.logsPath, this.maxLogs);
    } catch (error) {
      console.error('Error during cleanup:', error);
    }
  }

  /**
   * Clean up directory keeping only the newest files
   */
  cleanupDirectory(dirPath, maxFiles) {
    if (!fs.existsSync(dirPath)) {
      return;
    }

    const files = fs.readdirSync(dirPath)
      .map(file => ({
        name: file,
        path: path.join(dirPath, file),
        mtime: fs.statSync(path.join(dirPath, file)).mtime
      }))
      .sort((a, b) => b.mtime.getTime() - a.mtime.getTime());

    // Remove old files
    files.slice(maxFiles).forEach(file => {
      try {
        fs.unlinkSync(file.path);
        console.log(`Cleaned up old file: ${file.name}`);
      } catch (error) {
        console.error(`Failed to delete ${file.name}:`, error);
      }
    });
  }
}

// Export singleton instance
export default new Rageshake();