//
//  Daemon for IVPN Client Desktop
//  https://github.com/swapnilsparsh/devsVPN
//
//  Created by Stelnykovych Alexandr.
//  Copyright (c) 2023 IVPN Limited.
//
//  This file is part of the Daemon for IVPN Client Desktop.
//
//  The Daemon for IVPN Client Desktop is free software: you can redistribute it and/or
//  modify it under the terms of the GNU General Public License as published by the Free
//  Software Foundation, either version 3 of the License, or (at your option) any later version.
//
//  The Daemon for IVPN Client Desktop is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
//  or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
//  details.
//
//  You should have received a copy of the GNU General Public License
//  along with the Daemon for IVPN Client Desktop. If not, see <https://www.gnu.org/licenses/>.
//

package rageshake

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/swapnilsparsh/devsVPN/daemon/logger"
	"github.com/swapnilsparsh/devsVPN/daemon/service/platform"
	"github.com/swapnilsparsh/devsVPN/daemon/shell"
	"github.com/swapnilsparsh/devsVPN/daemon/version"
)

var log = logger.NewLogger("rgshk")

const (
	MAX_LOG_SIZE = 4 * 1048576 // 4 MB max per logfile
)

// CrashReport represents a complete crash report
type CrashReport struct {
	Timestamp      string                 `json:"timestamp"`
	CrashType      string                 `json:"crash_type"`
	System         SystemInfo             `json:"system"`
	Logs           LogInfo                `json:"logs"`
	NetworkInfo    NetworkInfo            `json:"network_info"`
	ProcessInfo    ProcessInfo            `json:"process_info"`
	AdditionalData map[string]interface{} `json:"additional_data,omitempty"`
}

// SystemInfo contains system information
type SystemInfo struct {
	Platform      string     `json:"platform"`
	Architecture  string     `json:"architecture"`
	GoVersion     string     `json:"go_version"`
	DaemonVersion string     `json:"daemon_version"`
	OSInfo        OSInfo     `json:"os_info"`
	MemoryInfo    MemoryInfo `json:"memory_info"`
	CPUInfo       CPUInfo    `json:"cpu_info"`
}

// OSInfo contains operating system information
type OSInfo struct {
	Platform     string `json:"platform"`
	Release      string `json:"release"`
	Architecture string `json:"architecture"`
	Hostname     string `json:"hostname"`
	Username     string `json:"username"`
	HomeDir      string `json:"home_dir"`
	WorkingDir   string `json:"working_dir"`
}

// MemoryInfo contains memory information
type MemoryInfo struct {
	TotalMemory        uint64  `json:"total_memory"`
	FreeMemory         uint64  `json:"free_memory"`
	UsedMemory         uint64  `json:"used_memory"`
	MemoryUsagePercent float64 `json:"memory_usage_percent"`
}

// CPUInfo contains CPU information
type CPUInfo struct {
	NumCPU       int `json:"num_cpu"`
	NumGoroutine int `json:"num_goroutine"`
	GoMaxProcs   int `json:"go_max_procs"`
}

// LogInfo contains log file information
type LogInfo struct {
	ActiveLog       string `json:"active_log,omitempty"`
	PreviousLog     string `json:"previous_log,omitempty"`
	LogSize         int64  `json:"log_size"`
	PreviousLogSize int64  `json:"previous_log_size"`
}

// NetworkInfo contains network configuration
type NetworkInfo struct {
	Interfaces   string `json:"interfaces"`
	RoutingTable string `json:"routing_table"`
	DNSConfig    string `json:"dns_config"`
}

// ProcessInfo contains process information
type ProcessInfo struct {
	PID         int               `json:"pid"`
	PPID        int               `json:"ppid"`
	CommandLine string            `json:"command_line"`
	WorkingDir  string            `json:"working_dir"`
	Environment map[string]string `json:"environment"`
}

// Rageshake handles crash reporting
type Rageshake struct {
	maxLogSize int64
}

// New creates a new Rageshake instance
func New() *Rageshake {
	return &Rageshake{
		maxLogSize: 4 * 1048576, // 4MB
	}
}

// CollectCrashReport generates a complete crash report
func (r *Rageshake) CollectCrashReport(crashType string, additionalData map[string]interface{}) (*CrashReport, error) {
	report := &CrashReport{
		Timestamp:      time.Now().UTC().Format(time.RFC3339),
		CrashType:      crashType,
		System:         r.collectSystemInfo(),
		Logs:           r.collectLogInfo(),
		NetworkInfo:    r.collectNetworkInfo(),
		ProcessInfo:    r.collectProcessInfo(),
		AdditionalData: additionalData,
	}

	return report, nil
}

// collectSystemInfo collects system information
func (r *Rageshake) collectSystemInfo() SystemInfo {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	hostname, _ := os.Hostname()
	username := os.Getenv("USER")
	if username == "" {
		username = os.Getenv("USERNAME")
	}
	homeDir, _ := os.UserHomeDir()
	workingDir, _ := os.Getwd()

	return SystemInfo{
		Platform:      runtime.GOOS,
		Architecture:  runtime.GOARCH,
		GoVersion:     runtime.Version(),
		DaemonVersion: version.GetFullVersion(),
		OSInfo: OSInfo{
			Platform:     runtime.GOOS,
			Release:      r.getOSRelease(),
			Architecture: runtime.GOARCH,
			Hostname:     hostname,
			Username:     username,
			HomeDir:      homeDir,
			WorkingDir:   workingDir,
		},
		MemoryInfo: MemoryInfo{
			TotalMemory:        memStats.Sys,
			FreeMemory:         memStats.Sys - memStats.Alloc,
			UsedMemory:         memStats.Alloc,
			MemoryUsagePercent: float64(memStats.Alloc) / float64(memStats.Sys) * 100,
		},
		CPUInfo: CPUInfo{
			NumCPU:       runtime.NumCPU(),
			NumGoroutine: runtime.NumGoroutine(),
			GoMaxProcs:   runtime.GOMAXPROCS(0),
		},
	}
}

// collectLogInfo collects log file information
func (r *Rageshake) collectLogInfo() LogInfo {
	logPath := platform.LogFile()
	prevLogPath := logPath + ".0"

	activeLog := r.readFileSafely(logPath, r.maxLogSize)
	previousLog := r.readFileSafely(prevLogPath, r.maxLogSize)

	activeLogSize := int64(0)
	prevLogSize := int64(0)

	if stat, err := os.Stat(logPath); err == nil {
		activeLogSize = stat.Size()
	}
	if stat, err := os.Stat(prevLogPath); err == nil {
		prevLogSize = stat.Size()
	}

	return LogInfo{
		ActiveLog:       activeLog,
		PreviousLog:     previousLog,
		LogSize:         activeLogSize,
		PreviousLogSize: prevLogSize,
	}
}

// collectNetworkInfo collects network information
func (r *Rageshake) collectNetworkInfo() NetworkInfo {
	interfaces := r.getNetworkInterfaces()
	routingTable := r.getRoutingTable()
	dnsConfig := r.getDNSConfig()

	return NetworkInfo{
		Interfaces:   interfaces,
		RoutingTable: routingTable,
		DNSConfig:    dnsConfig,
	}
}

// collectProcessInfo collects process information
func (r *Rageshake) collectProcessInfo() ProcessInfo {
	pid := os.Getpid()
	ppid := os.Getppid()
	workingDir, _ := os.Getwd()

	// Get command line arguments
	cmdLine := strings.Join(os.Args, " ")

	// Get environment variables (filtered for security)
	env := make(map[string]string)
	for _, envVar := range os.Environ() {
		parts := strings.SplitN(envVar, "=", 2)
		if len(parts) == 2 {
			key := parts[0]
			value := parts[1]

			// Filter out sensitive environment variables
			if !r.isSensitiveEnvVar(key) {
				env[key] = value
			}
		}
	}

	return ProcessInfo{
		PID:         pid,
		PPID:        ppid,
		CommandLine: cmdLine,
		WorkingDir:  workingDir,
		Environment: env,
	}
}

// readFileSafely reads a file safely with size limits
func (r *Rageshake) readFileSafely(filePath string, maxSize int64) string {
	stat, err := os.Stat(filePath)
	if err != nil {
		return fmt.Sprintf("[File not found: %s]", filePath)
	}

	if stat.Size() > maxSize {
		return fmt.Sprintf("[File too large: %d bytes, max: %d bytes]", stat.Size(), maxSize)
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Sprintf("[Error reading file: %v]", err)
	}

	return string(data)
}

// getOSRelease gets OS release information
func (r *Rageshake) getOSRelease() string {
	switch runtime.GOOS {
	case "linux":
		// Try to read /etc/os-release
		if data, err := os.ReadFile("/etc/os-release"); err == nil {
			lines := strings.Split(string(data), "\n")
			for _, line := range lines {
				if strings.HasPrefix(line, "PRETTY_NAME=") {
					return strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), "\"")
				}
			}
		}
		// Fallback to uname
		if output, _, _, _, err := shell.ExecAndGetOutput(nil, 1024, "", "uname", "-a"); err == nil {
			return strings.TrimSpace(output)
		}
	case "darwin":
		if output, _, _, _, err := shell.ExecAndGetOutput(nil, 1024, "", "sw_vers", "-productVersion"); err == nil {
			return "macOS " + strings.TrimSpace(output)
		}
	case "windows":
		if output, _, _, _, err := shell.ExecAndGetOutput(nil, 1024, "", "ver"); err == nil {
			return strings.TrimSpace(output)
		}
	}
	return "Unknown"
}

// getNetworkInterfaces gets network interface information
func (r *Rageshake) getNetworkInterfaces() string {
	var cmd string
	var args []string

	switch runtime.GOOS {
	case "linux":
		cmd = "ip"
		args = []string{"addr", "show"}
	case "darwin":
		cmd = "ifconfig"
		args = []string{"-a"}
	case "windows":
		cmd = "ipconfig"
		args = []string{"/all"}
	default:
		return "[Unsupported platform]"
	}

	output, _, _, _, err := shell.ExecAndGetOutput(nil, 1024*10, "", cmd, args...)
	if err != nil {
		return fmt.Sprintf("[Error getting network interfaces: %v]", err)
	}

	return output
}

// getRoutingTable gets routing table information
func (r *Rageshake) getRoutingTable() string {
	var cmd string
	var args []string

	switch runtime.GOOS {
	case "linux":
		cmd = "ip"
		args = []string{"route", "show"}
	case "darwin":
		cmd = "netstat"
		args = []string{"-nr"}
	case "windows":
		cmd = "route"
		args = []string{"print"}
	default:
		return "[Unsupported platform]"
	}

	output, _, _, _, err := shell.ExecAndGetOutput(nil, 1024*10, "", cmd, args...)
	if err != nil {
		return fmt.Sprintf("[Error getting routing table: %v]", err)
	}

	return output
}

// getDNSConfig gets DNS configuration
func (r *Rageshake) getDNSConfig() string {
	var cmd string
	var args []string

	switch runtime.GOOS {
	case "linux":
		cmd = "cat"
		args = []string{"/etc/resolv.conf"}
	case "darwin":
		cmd = "scutil"
		args = []string{"--dns"}
	case "windows":
		cmd = "ipconfig"
		args = []string{"/displaydns"}
	default:
		return "[Unsupported platform]"
	}

	output, _, _, _, err := shell.ExecAndGetOutput(nil, 1024*10, "", cmd, args...)
	if err != nil {
		return fmt.Sprintf("[Error getting DNS config: %v]", err)
	}

	return output
}

// isSensitiveEnvVar checks if an environment variable is sensitive
func (r *Rageshake) isSensitiveEnvVar(key string) bool {
	sensitiveKeys := []string{
		"PASSWORD", "SECRET", "KEY", "TOKEN", "AUTH", "CREDENTIAL",
		"PRIVATE", "SIGNATURE", "HASH", "SALT", "IV", "NONCE",
	}

	upperKey := strings.ToUpper(key)
	for _, sensitive := range sensitiveKeys {
		if strings.Contains(upperKey, sensitive) {
			return true
		}
	}
	return false
}

// SaveCrashReport saves a crash report to a file
func (r *Rageshake) SaveCrashReport(report *CrashReport, outputPath string) error {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal crash report: %w", err)
	}

	// Ensure directory exists
	dir := filepath.Dir(outputPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	if err := os.WriteFile(outputPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write crash report: %w", err)
	}

	log.Info(fmt.Sprintf("Crash report saved to: %s", outputPath))
	return nil
}

// GetCrashReportAsString returns crash report as a formatted string
func (r *Rageshake) GetCrashReportAsString(report *CrashReport) string {
	var builder strings.Builder

	builder.WriteString("=== CRASH REPORT ===\n")
	builder.WriteString(fmt.Sprintf("Timestamp: %s\n", report.Timestamp))
	builder.WriteString(fmt.Sprintf("Crash Type: %s\n", report.CrashType))
	builder.WriteString(fmt.Sprintf("Platform: %s\n", report.System.Platform))
	builder.WriteString(fmt.Sprintf("Architecture: %s\n", report.System.Architecture))
	builder.WriteString(fmt.Sprintf("Daemon Version: %s\n", report.System.DaemonVersion))
	builder.WriteString(fmt.Sprintf("Go Version: %s\n", report.System.GoVersion))
	builder.WriteString(fmt.Sprintf("Hostname: %s\n", report.System.OSInfo.Hostname))
	builder.WriteString(fmt.Sprintf("Username: %s\n", report.System.OSInfo.Username))
	builder.WriteString(fmt.Sprintf("Working Directory: %s\n", report.System.OSInfo.WorkingDir))
	builder.WriteString(fmt.Sprintf("PID: %d\n", report.ProcessInfo.PID))
	builder.WriteString(fmt.Sprintf("PPID: %d\n", report.ProcessInfo.PPID))
	builder.WriteString(fmt.Sprintf("Command Line: %s\n", report.ProcessInfo.CommandLine))
	builder.WriteString(fmt.Sprintf("Memory Usage: %.2f%%\n", report.System.MemoryInfo.MemoryUsagePercent))
	builder.WriteString(fmt.Sprintf("Goroutines: %d\n", report.System.CPUInfo.NumGoroutine))

	if len(report.AdditionalData) > 0 {
		builder.WriteString("\n=== ADDITIONAL DATA ===\n")
		for key, value := range report.AdditionalData {
			builder.WriteString(fmt.Sprintf("%s: %v\n", key, value))
		}
	}

	return builder.String()
}

// CleanupOldCrashReports cleans up old crash report files
func (r *Rageshake) CleanupOldCrashReports(reportsDir string, maxAge time.Duration) error {
	if _, err := os.Stat(reportsDir); os.IsNotExist(err) {
		return nil // Directory doesn't exist, nothing to clean
	}

	entries, err := os.ReadDir(reportsDir)
	if err != nil {
		return fmt.Errorf("failed to read reports directory: %w", err)
	}

	cutoff := time.Now().Add(-maxAge)

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		if !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}

		filePath := filepath.Join(reportsDir, entry.Name())
		info, err := entry.Info()
		if err != nil {
			log.Warning(fmt.Sprintf("Failed to get file info for %s: %v", filePath, err))
			continue
		}

		if info.ModTime().Before(cutoff) {
			if err := os.Remove(filePath); err != nil {
				log.Warning(fmt.Sprintf("Failed to remove old crash report %s: %v", filePath, err))
			} else {
				log.Info(fmt.Sprintf("Cleaned up old crash report: %s", filePath))
			}
		}
	}

	return nil
}
