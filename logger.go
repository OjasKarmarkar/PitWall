package main

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/natefinch/lumberjack.v2"
)

const logFile = "pitwall.log"

// initLogger sets up the global slog logger backed by lumberjack for file
// rotation and stdout for live tailing. The log file (and any rotated backups
// from the previous run) are removed on every startup so each run starts with
// a clean log. Lumberjack rotates the active file when it exceeds 25 MB;
// rotated files from the current run are cleaned on the next restart.
func initLogger() {
	clearOldLogs()

	lj := &lumberjack.Logger{
		Filename:   logFile,
		MaxSize:    25, // megabytes — rotate when file exceeds this
		MaxBackups: 0,  // lumberjack default: retain all; cleared each restart
		Compress:   false,
	}

	w := io.MultiWriter(os.Stdout, lj)
	handler := slog.NewTextHandler(w, &slog.HandlerOptions{Level: slog.LevelInfo})
	slog.SetDefault(slog.New(handler))
}

// clearOldLogs removes the active log file and any lumberjack-rotated backups
// (pattern: pitwall-<timestamp>.log) so each restart begins with a clean slate.
func clearOldLogs() {
	os.Remove(logFile)

	ext := filepath.Ext(logFile)
	prefix := strings.TrimSuffix(logFile, ext)
	matches, _ := filepath.Glob(prefix + "-*" + ext)
	for _, m := range matches {
		os.Remove(m)
	}
}
