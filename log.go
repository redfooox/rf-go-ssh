package rSwitch

import (
	"fmt"
	"log"
	"os"
)

var IsDebug = false

func init() {

	logError := log.New(os.Stdout, "[error]", log.Lshortfile|log.Ldate|log.Lmicroseconds)
	logError.Println("test")

	logDebug := log.New(os.Stdout, "[debug]", log.Lshortfile|log.Ldate|log.Lmicroseconds)
	logDebug.Println("test")

	logInfo := log.New(os.Stdout, "[info] ", log.Lshortfile|log.Ldate|log.Lmicroseconds)
	logInfo.Println("test")

}

// LogError 打印错误日志
func LogError(format string, a ...interface{}) {
	log.SetFlags(log.Lshortfile | log.Ldate)
	log.Println("[error]:" + fmt.Sprintf(format, a...))
	//fmt.Println("[error]:" + fmt.Sprintf(format, a...))
}

// LogDebug 打印debug日志
func LogDebug(format string, a ...interface{}) {
	if IsDebug {
		log.SetFlags(log.Lshortfile | log.Ldate | log.Lmicroseconds)
		log.Println("[DEBUG]:" + fmt.Sprintf(format, a...))
		fmt.Println("[DEBUG]:" + fmt.Sprintf(format, a...))
	}
}

// LogInfo 打印info日志
func LogInfo(format string, a ...interface{}) {
	log.SetFlags(log.Lshortfile | log.Ldate)
	log.Println("[INFO]:" + fmt.Sprintf(format, a...))
	//fmt.Println("[INFO]:" + fmt.Sprintf(format, a...))

}
