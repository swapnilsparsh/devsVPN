# Rageshake Crash Reporting Setup

This document describes the Rageshake crash reporting system implemented in the PrivateLINE Connect desktop application.

## Overview

Rageshake is a comprehensive crash reporting system that collects system information, logs, and crash data when the application encounters errors or crashes. It's based on the [Matrix Rageshake API specification](https://github.com/matrix-org/rageshake/blob/main/docs/api.md) and provides detailed diagnostic information for debugging.

## Architecture

The Rageshake system consists of two main components:

### 1. UI Component (Electron)
- **Location**: `ui/src/rageshake/`
- **Purpose**: Handles crash reporting in the Electron main process
- **Features**:
  - Electron crash reporter integration
  - Crash dump collection
  - System information gathering
  - User dialog for crash report actions
  - **Matrix Rageshake API compliance** - Follows the official Rageshake API specification

### 2. Daemon Component (Go)
- **Location**: `daemon/rageshake/rageshake.go`
- **Purpose**: Handles crash reporting in the Go daemon
- **Features**:
  - System information collection
  - Network configuration gathering
  - Process information collection
  - Log file analysis
  - Crash report generation and storage

## Features

### Crash Reporting
- **Automatic Detection**: Catches uncaught exceptions and unhandled rejections
- **Manual Triggering**: Allows users to manually generate crash reports
- **Comprehensive Data**: Collects system info, logs, crash dumps, and metadata
- **Matrix Rageshake API**: Follows the official Rageshake API specification

### System Readiness Check
- **Comprehensive Testing**: Validates all system components
- **Configuration Verification**: Checks server URLs and settings
- **File System Permissions**: Verifies write access to required directories
- **Network Connectivity**: Tests server accessibility and DNS resolution
- **API Compatibility**: Ensures required APIs are available
- **Crash Reporter**: Validates Electron crash reporter setup
- **Log Collection**: Tests system information gathering
- **Test Submission**: Performs actual test submission to server

### Collected Information
- **System Info**: OS, architecture, versions
- **Memory Info**: Memory usage statistics
- **CPU Info**: CPU cores, goroutines
- **Network Info**: Interfaces, routing, DNS
- **Process Info**: PID, command line, environment
- **Log Files**: Application and system logs
- **Crash Dumps**: Electron crash dumps (if available)

### User Interface
- **Crash Report Dialog**: Shows when crashes occur
- **Options**: Send report, save locally, or cancel
- **Progress Feedback**: Shows what data is being collected

## Integration Points

### UI Integration
1. **Background Process**: Initialized in `ui/src/background.js`
2. **IPC Handlers**: Added to `ui/src/ipc/main-listener.js`
3. **Renderer API**: Available via `ui/src/ipc/renderer-sender.js`
4. **Error Handling**: Automatic crash detection and reporting
5. **Rageshake API**: Proper API client in `ui/src/rageshake/api.js`

### File Structure
```
ui/src/rageshake/
├── index.js                    # Main Rageshake module
├── config.js                   # Configuration settings
├── api.js                      # Rageshake API client
└── test-connection.js          # Server testing utilities
```

### Daemon Integration
1. **Service Integration**: Added to `daemon/service/service.go`
2. **Protocol Handlers**: Added to `daemon/protocol/protocol.go`
3. **Type Definitions**: Added to `daemon/protocol/types/`
4. **Error Recovery**: Panic recovery with crash reporting

## Usage

### For Users
1. When a crash occurs, a dialog will appear asking if you want to send a crash report
2. You can choose to:
   - Send the report to PrivateLINE
   - Save the report locally
   - Cancel the operation
3. The report contains system information and logs to help diagnose the issue

### For Developers
1. **Manual Testing**: Use the `RageshakeTest.vue` component
2. **Server Testing**: Use the "Test Server Connection" button to verify server connectivity
3. **API Usage**:
   ```javascript
   // Generate a crash report
   await sender.GenerateCrashReport('manual', { additionalData: 'test' });
   
   // Collect crash report data
   const report = await sender.CollectCrashReport('manual', {});
   
   // Test server connection
   const connectionTest = await sender.TestRageshakeConnection();
   ```

### For System Administrators
1. **Crash Reports Location**: 
   - UI: `%APPDATA%/PrivateLINE Connect/CrashReports/` (Windows)
   - UI: `~/Library/Application Support/PrivateLINE Connect/CrashReports/` (macOS)
   - UI: `~/.config/PrivateLINE Connect/CrashReports/` (Linux)
   - Daemon: Platform-specific log directories

2. **Configuration**: Crash reporting can be enabled/disabled in settings

## Configuration

### Server Configuration
- **Base URL**: `https://logs.privateline.io`
- **Upload Endpoint**: `/api/submit`
- **Full Upload URL**: `https://logs.privateline.io/api/submit`
- **Configuration File**: `ui/src/rageshake/config.js`

### Rageshake API Format
The system follows the [official Matrix Rageshake API specification](https://github.com/matrix-org/rageshake/blob/main/docs/api.md):

**Required Fields:**
- `text` - Textual description of the problem
- `user_agent` - Application user-agent
- `app` - Application identifier (e.g., 'privateline-connect')
- `version` - Application version
- `label` - Label for the report (e.g., 'crash-report')

**Optional Fields:**
- `log` - Log files (multiple allowed)
- `compressed-log` - Gzipped log files (multiple allowed)
- `file` - Additional files (multiple allowed)
- Additional metadata fields as name/value pairs

**Data Format:**
- Uses `multipart/form-data` for file uploads
- Logs are sent as individual `log` fields
- Compressed logs are sent as `compressed-log` fields
- Additional files are sent as `file` fields
- Metadata is sent as additional form fields
- Response includes `report_url` for tracking

### Sentry Integration
- **DSN**: Configured in `ui/src/sentry/dsn.js`
- **Upload URL**: Set to `https://logs.privateline.io/rageshake`
- **Data Limits**: Maximum 10MB per report
- **Compression**: Enabled for large reports

### File Management
- **Max Crash Dumps**: 10 files
- **Max Log Files**: 5 files
- **Max Log Size**: 64KB per log file
- **Auto Cleanup**: Old reports are automatically cleaned up

## Security Considerations

### Data Privacy
- **Account Information**: Partially anonymized (last 6 characters shown)
- **Environment Variables**: Sensitive variables are filtered out
- **File Content**: Large files are truncated to prevent excessive data collection
- **User Consent**: Users must explicitly choose to send reports

### Data Handling
- **Local Storage**: Reports can be saved locally for user review
- **Network Transmission**: Reports are sent over HTTPS
- **Data Retention**: Reports are subject to Sentry's retention policies

## Troubleshooting

### Common Issues
1. **Crash Reporter Not Initialized**: Check if Rageshake is properly imported and initialized
2. **Permission Errors**: Ensure the application has write permissions to user data directory
3. **Network Issues**: Crash reports can be saved locally if network is unavailable
4. **Large Reports**: Reports are automatically compressed and truncated if too large
5. **Server Connection Issues**: Use the connection test to verify server accessibility

### Server Connectivity Troubleshooting
1. **Test Server Connection**: Use the test button in the RageshakeTest component
2. **Check Network**: Ensure the application can reach `https://logs.privateline.io`
3. **Firewall Issues**: Verify that outbound HTTPS connections are allowed
4. **DNS Issues**: Check if the domain resolves correctly
5. **Server Status**: Verify that the Rageshake server is running and accessible

### Debug Mode
- Enable debug logging to see Rageshake initialization and operation
- Check console for error messages during crash report generation
- Verify IPC communication between UI and daemon

## Future Enhancements

### Planned Features
1. **Custom Crash Report Types**: Allow applications to define custom crash types
2. **Enhanced UI**: Better crash report viewer and management
3. **Batch Reporting**: Collect multiple crashes and send together
4. **Analytics**: Crash frequency and pattern analysis
5. **Integration**: Better integration with existing diagnostic tools

### API Extensions
1. **Custom Data Collection**: Allow applications to add custom data to crash reports
2. **Report Filtering**: Filter reports based on severity or type
3. **Report Templates**: Customizable report formats
4. **Webhook Integration**: Send reports to custom endpoints

## Support

For issues with the Rageshake system:
1. Check the application logs for error messages
2. Verify the crash report files are being generated
3. Test the system using the provided test component
4. Contact the development team with specific error details 

## Server Requirements

Your `https://logs.privateline.io/api/submit` endpoint should implement the [official Matrix Rageshake API specification](https://github.com/matrix-org/rageshake/blob/main/docs/api.md):

### API Endpoints
- **POST** `/api/submit` - Accept crash report submissions

### Required Features
1. **Accept multipart/form-data** with the following fields:
   - `text` (string) - Textual description of the problem
   - `user_agent` (string) - Application user-agent
   - `app` (string) - Application identifier
   - `version` (string) - Application version
   - `label` (string) - Label for the report
   - `log` (file) - Log files (multiple allowed)
   - `compressed-log` (file) - Gzipped log files (multiple allowed)
   - `file` (file) - Additional files (multiple allowed)

2. **Handle file uploads** for:
   - Log files (text format, .log or .txt extensions)
   - Compressed log files (gzip format)
   - Additional files (various formats: jpg, png, txt, json, txt.gz, json.gz)

3. **Return appropriate responses**:
   - **200 OK** - Report accepted successfully
   - **400 Bad Request** - Invalid data format
   - **413 Payload Too Large** - File too large
   - **500 Internal Server Error** - Server error

4. **Support CORS** if needed for web-based testing

5. **Handle large payloads** (up to 10MB total)

### Response Format
The server should return a JSON response with:
```json
{
  "report_url": "https://logs.privateline.io/report/abc123"
}
```

The `report_url` field is optional and omitted if issue submission is disabled.