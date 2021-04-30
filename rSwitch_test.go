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
	IsDebug = true
	sw, err := NewSwitchConnect("10.138.152.205", "22", "admin", "G63__Paq")

	if err != nil {
		t.Error("Switch对象初始化失败")
	}
	println(sw.OutLog)
	output, _ := sw.RunCommands("dis power", "dis cu")
	println(output)

	println(sw.OutLog)

	//output := sw.readChannel(time.Second * 5, ">", "]")
	//fmt.Println(output)
	//output := sw.ReadChannelExpect(time.Second * 5, ">", "]")

	//temp := <-sw.outChan
	//println(temp)

}

// 测试生成Switch对象功能
func TestNewSwitchConnectPasswordError(t *testing.T) {
	_, err := NewSwitchConnect("10.138.152.205", "22", "admin", "G63__")

	if err != nil {
		t.Error("Switch对象初始化失败")
	}

}
