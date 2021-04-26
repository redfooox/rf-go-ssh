package rSwitch

import "fmt"

var IsDebug = false

// LogError 打印错误日志
func LogError(format string, a ...interface{}) {
	fmt.Println("[error]:" + fmt.Sprintf(format, a...))
}

// LogDebug 打印debug日志
func LogDebug(format string, a ...interface{}) {
	if IsDebug {
		fmt.Println("[DEBUG]:" + fmt.Sprintf(format, a...))
	}
}

// LogInfo 打印info日志
func LogInfo(format string, a ...interface{}) {
	fmt.Println("[INFO]:" + fmt.Sprintf(format, a...))
}
