# rf-go-ssh

基于go语言的交换机ssh工具。 （huawei-switch）

## version 0.1.0

### `Switch`数据结构

`Switch`数据结构主要存放连接交换机需要使用的相关配置、会话、日志文件。

```go
type Switch struct{
ip          string // 设备IP地址
port        string // 交换机端口
username    string // 登录设备用户名
password    string   // 登录设备密码
cmds        []string // 执行命令
session     *ssh.Session // 设备连接会话
inChan      chan string  // 输入通道
outChan     chan string  // 输出通道
lastUseTime time.Time    // 连接时间
OutLog      string       // 输出交互内容
Logger      *log.Logger // 日志记录
}
```

---

### `NewSwitchConnect()`

创建`Switch`结构体，初始化ssh连接。配置回显不分页。返回类型：`Switch`。

```go
func NewSwitchConnect(ip, port, username, password string, )
```

初始化`Switch`，创建与交换机的连接

---

### `Switch.RunCommands(cmds ...string) (string, []string, error)`

初始化

## 相关开源包

[uuid](https://github.com/google/uuid)
[logrus](https://github.com/sirupsen/logrus)
[ssh](https://github.com/crypto/ssh)
