package rSwitch

import (
	"testing"
	"time"
)

// 测试初始化Switch
func TestSwitch(t *testing.T) {
	testSwitch1 := Switch{
		ip:          "10.138.152.205",
		port:        "22",
		username:    "admin",
		password:    "huawei@123",
		cmds:        []string{"dis power"},
		lastUseTime: time.Now(),
		OutLog:      "",
	}
	t.Log(testSwitch1)
}

// 测试生成Switch对象功能
func TestNewSwitchConnect(t *testing.T) {
	//WorkMode = logrus.DebugLevel
	sw, err := NewSwitchConnect("10.138.152.205", "22", "admin", "huawei@123")
	if err != nil {
		t.Log(err)
		t.Log(err.Error())
		//t.Error("Switch对象初始化失败")
		return
	}
	//println(sw.OutLog)
	_, output, _ := sw.RunCommands("dis power", "dis cu")
	t.Log(len(output))
	//t.Log(output[2])
	//t.Log(output)

}

// 测试生成Switch对象功能
func TestNewSwitchConnectPasswordError(t *testing.T) {
	_, err := NewSwitchConnect("10.138.152.205", "22", "admin", "G63__")

	if err != nil {
		t.Error("Switch对象初始化失败")
	}

}

// 测试多线程连接ssh
func TestNewGoSwitchRunCommands(t *testing.T) {

	switchsInfo := [...]map[string]string{
		{"ip": "10.138.152.205", "port": "22", "username": "admin", "password": "huawei@123", "cmds": "dis power"},
		{"ip": "10.138.152.205", "port": "22", "username": "admin", "password": "huawei@123", "cmds": "dis int d"},
	}
	for _, switchInfo := range switchsInfo {
		goSwitchRunCommands(switchInfo, switchInfo["cmds"], switchInfo["cmds"])
	}
	Wg.Wait() // 阻塞至所有线程执行完毕

}
