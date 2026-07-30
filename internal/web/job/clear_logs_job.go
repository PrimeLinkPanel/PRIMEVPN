package job

import (
	"os"

	"github.com/mhsanaei/PRIMEVPN/v3/internal/logger"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/xray"
)

const defaultMaxXrayLogBytes int64 = 64 << 20

var maxXrayLogBytes = defaultMaxXrayLogBytes

// ClearLogsJob clears configured Xray logs during the daily cleanup.
type ClearLogsJob struct{}

// PruneXrayLogsJob caps configured Xray logs during normal operation.
type PruneXrayLogsJob struct{}

// NewClearLogsJob creates a new daily log cleanup job.
func NewClearLogsJob() *ClearLogsJob {
	return new(ClearLogsJob)
}

// NewPruneXrayLogsJob creates a new periodic Xray log pruning job.
func NewPruneXrayLogsJob() *PruneXrayLogsJob {
	return new(PruneXrayLogsJob)
}

// Run clears configured Xray access and error logs during daily cleanup.
//
// PRIMEVPN's native client-IP enforcement does not consume legacy IP-limit
// or banned-IP log files, so those files are neither created nor rotated.
func (j *ClearLogsJob) Run() {
	wipeXrayLogs()
}

// Run truncates an access or error log only after it exceeds the configured
// limit. This prevents an active log from growing without bound between daily
// cleanup runs.
func (j *PruneXrayLogsJob) Run() {
	truncateXrayLog(xray.GetAccessLogPath, maxXrayLogBytes)
	truncateXrayLog(xray.GetErrorLogPath, maxXrayLogBytes)
}

func wipeXrayLogs() {
	truncateXrayLog(xray.GetAccessLogPath, 0)
	truncateXrayLog(xray.GetErrorLogPath, 0)
}

func truncateXrayLog(
	pathFn func() (string, error),
	maxBytes int64,
) {
	logPath, err := pathFn()
	if err != nil || disabledXrayLogPath(logPath) {
		return
	}

	if maxBytes > 0 {
		info, statErr := os.Stat(logPath)
		if statErr != nil {
			if !os.IsNotExist(statErr) {
				logger.Warning(
					"Failed to stat Xray log:",
					logPath,
					"-",
					statErr,
				)
			}
			return
		}

		if info.Size() <= maxBytes {
			return
		}
	}

	if truncateErr := os.Truncate(logPath, 0); truncateErr != nil &&
		!os.IsNotExist(truncateErr) {
		logger.Warning(
			"Failed to truncate Xray log:",
			logPath,
			"-",
			truncateErr,
		)
	}
}

func disabledXrayLogPath(path string) bool {
	return path == "" || path == "none"
}
