package rSwitch

import (
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
	"io"
	"net"
	"os"
	"strings"
	"time"
)

var (
	workTime  = time.Now()
	logFields = log.Fields{}
	WorkMode  = log.InfoLevel
)

func (sw *Switch) init() {
	// 初始化日志文件夹
	path := "log/" + workTime.Format("2006-01-02")
	err := os.MkdirAll(path, 0777)
	if err != nil {
		// 初始化目录失败
		log.Error("初始化目录失败")
	}

	// 创建日志文件
	logFile, err := os.OpenFile(path+"/r.log",
		os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalln("打开日志文件失败:", err)
	}
	sw.Logger = log.New()

	// 默认日志携带信息
	logFields = log.Fields{
		"ip":       sw.ip,
		"username": sw.username,
	}

	// 设置将日志输出到标准输出（默认的输出为stderr，标准错误）
	// 日志消息输出可以是任意的io.writer类型
	sw.Logger.SetOutput(io.MultiWriter(logFile, os.Stdout))
	// 设置日志级别为warn以上
	sw.Logger.SetLevel(WorkMode)
	//sw.Logger.SetLevel(log.WarnLevel)
	//sw.Logger.SetLevel(log.DebugLevel)
	// 为当前logrus实例设置消息输出格式为text格式。
	// 同样地，也可以单独为某个logrus实例设置日志级别和hook，这里不详细叙述。
	sw.Logger.Formatter = &log.JSONFormatter{}
	//sw.Logger.Formatter = &log.TextFormatter{}
	sw.Logger.WithFields(logFields).Debug("sw初始化完成")
}

type Switch struct {
	ip          string       // 设备IP地址
	port        string       // 交换机端口
	username    string       // 登录设备用户名
	password    string       // 登录设备密码
	cmds        []string     // 执行命令
	session     *ssh.Session // 设备连接会话
	inChan      chan string  // 输入通道
	outChan     chan string  // 输出通道
	lastUseTime time.Time    // 连接时间
	OutLog      string       // 输出交互内容
	Logger      *log.Logger  // 日志记录
}

// NewSwitchConnect 创建新会话
func NewSwitchConnect(ip, port, username, password string) (*Switch, error) {

	log.Info("[begin]设备连接")

	sw := Switch{
		ip:       ip,
		port:     port,
		username: username,
		password: password,
	}
	// 初始化日志等
	sw.init()

	sw.Logger.WithFields(logFields).Info("设备连接中")

	// 创建客户端会话
	if err := sw.createClientSession(); err != nil {
		sw.Logger.WithFields(logFields).Errorf("[end|error]创建客户端会话失败.%s", err.Error())
		return nil, err
	}

	// 绑定pty连接，初始化管道
	if err := sw.connectPty(); err != nil {
		sw.Logger.WithFields(logFields).Errorf("[end|error]pty、管道绑定失败.%s", err.Error())
		return nil, err
	}

	// 连接设备
	if err := sw.startShell(); err != nil {
		sw.Logger.WithFields(logFields).Errorf("[end|error]连接远端设备失败.%s", err.Error())
		return nil, err
	}

	// 取消回显分页
	if err := sw.setScreenLength(); err != nil {
		sw.Logger.WithFields(logFields).Errorf("[end|error]取消回显分页:%s", err.Error())
		return nil, err
	}

	sw.lastUseTime = time.Now() //修改设备登录时间
	sw.Logger.WithFields(logFields).Info("[end|success]设备连接")

	sw.Logger.WithFields(logFields).Info("设备连接成功")

	return &sw, nil

}

// createClientSession 创建客户端会话
/*
@Description 创建客户端会话
@return 执行错误
*/
func (sw *Switch) createClientSession() error {
	sw.Logger.WithFields(logFields).Debug("[begin]初始化设备参数")
	config := ssh.ClientConfig{
		User: sw.username,
		Auth: []ssh.AuthMethod{
			ssh.Password(sw.password),
		},
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return nil
		},
		Timeout: 20 * time.Second,
		Config: ssh.Config{
			Ciphers: []string{"aes128-ctr", "aes192-ctr", "aes256-ctr", "aes128-gcm@openssh.com",
				"arcfour256", "arcfour128", "aes128-cbc", "aes256-cbc", "3des-cbc", "des-cbc",
			},
			KeyExchanges: []string{
				"diffie-hellman-group-exchange-sha1", "diffie-hellman-group-sha1",
				"diffie-hellman-group-exchange-sha256",
			},
		},
	}
	sw.Logger.WithFields(logFields).Debug("[end|success]初始化设备参数.")

	// 创建客户端
	sw.Logger.WithFields(logFields).Debug("[begin]创建并配置客户端.")
	client, err := ssh.Dial("tcp", sw.ip+":"+sw.port, &config)
	if err != nil {
		sw.Logger.WithFields(logFields).Errorf("[end|error]创建客户端失败.%s", err.Error())
		return err

	}
	sw.Logger.WithFields(logFields).Debug("[end|success]创建并配置客户端成功.")

	// 创建会话
	sw.Logger.WithFields(logFields).Debug("[begin]客户端建立新会话.")
	session, err := client.NewSession()
	if err != nil {
		sw.Logger.WithFields(logFields).Errorf("[end|error]创建会话失败.%s", err.Error())
		return err
	}
	sw.Logger.WithFields(logFields).Debug("[end|success]客户端建立新会话成功.")
	sw.session = session

	return nil
}

// 客户端会话绑定远程连接，初始化输入&接收管道
func (sw *Switch) connectPty() error {
	sw.Logger.WithFields(logFields).Debug("[begin]绑定远程连接 初始化输入、输出管道.")
	defer func() {
		if err := recover(); err != nil {
			sw.Logger.WithFields(logFields).Errorf("SSHSession muxShell err:%s", err)
		}
	}()

	// 初始化终端模式
	modes := ssh.TerminalModes{
		ssh.ECHO:          1,     //disable echoing
		ssh.TTY_OP_ISPEED: 14400, // input speed = 14.4k baud
		ssh.TTY_OP_OSPEED: 14400, // output speed = 14.4k baud
	}

	sw.Logger.WithFields(logFields).Debug("[begin]远程会话连接.")
	if err := sw.session.RequestPty("vt100", 80, 40, modes); err != nil {
		sw.Logger.WithFields(logFields).Errorf("[end|error]远程会话连接失败.")
		return err
	}
	sw.Logger.WithFields(logFields).Debug("[end|success]远程会话成功.")

	sw.Logger.WithFields(logFields).Debug("[begin]初始化输入管道.")
	write, err := sw.session.StdinPipe()
	if err != nil {
		sw.Logger.WithFields(logFields).Debug("[end|error]初始化输入管道.")
	}
	sw.Logger.WithFields(logFields).Debug("[end|success]初始化输入管道.")

	sw.Logger.WithFields(logFields).Debug("[begin]初始化接收管道.")
	read, err := sw.session.StdoutPipe()
	if err != nil {
		sw.Logger.WithFields(logFields).Debug("[end|error]初始化接收管道.")
	}
	sw.Logger.WithFields(logFields).Debug("[end|success]初始化接收管道.")

	// 初始化带缓存的 输入接收通道
	//inChan := make(chan string, 1024)
	//outChan := make(chan string, 1024)

	sw.inChan = make(chan string, 1024)
	sw.outChan = make(chan string, 1024)

	// 线程发送、读取管道中内容
	//写通道
	go func() {
		defer func() {
			if err := recover(); err != nil {
				sw.Logger.WithFields(logFields).Errorf("[end|error]远程会话pty写入失败.%s", err)
			}
		}()
		for cmd := range sw.inChan {
			_, err := write.Write([]byte(cmd + "\n"))
			if err != nil {
				sw.Logger.WithFields(logFields).Debugf("[end|error]远程会话pty写入失败.%s", err.Error())
				return
			}
		}
	}()

	//接收通道
	go func() {
		defer func() {
			if err := recover(); err != nil {
				sw.Logger.WithFields(logFields).Debugf("[end|error]远程会话pty读取失败.%s", err)
			}
		}()
		var (
			buf [65 * 1024]byte
			t   int
		)
		for {
			n, err := read.Read(buf[t:])
			if err != nil {
				sw.Logger.WithFields(logFields).Debugf("[end|error]远程会话pty读取失败.%s", err.Error())
				return
			}
			t += n
			//println(string(buf[:t]))  // 注释注释打印
			sw.outChan <- string(buf[:t])
			t = 0
		}
	}()
	//sw.inChan = inChan
	//sw.outChan = outChan

	sw.Logger.WithFields(logFields).Debug("[end|success]绑定远程连接 初始化输入、输出管道成功.")
	return nil

}

// 连接远程设备
func (sw *Switch) startShell() error {
	sw.Logger.WithFields(logFields).Debug("[begin]连接设备.")
	if err := sw.session.Shell(); err != nil {
		sw.Logger.WithFields(logFields).Errorf("[end|error]连接设备失败.%s", err.Error())
		return err
	}
	sw.Logger.WithFields(logFields).Debug("[end|success]连接成功.")
	sw.readChannel(time.Second*5, ">", "]")
	return nil
}

// 取消回显分页
func (sw *Switch) setScreenLength() error {
	_, err := sw.RunCommands("screen-length 0 temporary")
	if err != nil {
		sw.Logger.WithFields(logFields).Errorf("取消回显失败.%s", err.Error())
		return err
	}

	return nil
}

// 读取接收管道内容
func (sw *Switch) readChannel(timeout time.Duration, expects ...string) string {
	sw.Logger.WithFields(logFields).Debug("[begin]读取管道内数据.")
	output := ""
	littleSleep := time.Millisecond * 10
	tempTimes := time.Millisecond // 睡的次数

getNowData:
	for {
		sw.Logger.WithFields(logFields).Debug("[sleep]等待10毫秒")
		time.Sleep(littleSleep) // 睡10毫秒
		tempTimes += littleSleep
		//当前通道内容
		select {
		case newData, ok := <-sw.outChan:
			if !ok {
				// 通道关闭停止读取
				sw.Logger.WithFields(logFields).Debug("[end|error]接收通道关闭")
				sw.OutLog += output
				return output
			}
			output += newData

		default:
			// 判断是否超时
			if tempTimes > timeout {
				sw.Logger.WithFields(logFields).Debug("[end|timeout]读取管道内数据成功.")
				break getNowData

			}
			// 判断结尾字符是否符合要求
			for _, expect := range expects {
				if strings.Contains(output, expect) {
					sw.Logger.WithFields(logFields).Debug("[end|success]读取管道内数据成功.")
					break getNowData
				}
				continue
			}
		}
	}
	sw.OutLog += output
	return output
}

// 写入通道内容
func (sw *Switch) writeChannel(cmds ...string) ([]string, error) {
	outputList := make([]string, 1)
	sw.Logger.WithFields(logFields).Debugf("[begin]执行命令:%v", cmds)
	for _, cmd := range cmds {
		sw.inChan <- cmd
		output := sw.readChannel(time.Second*5, ">", "]")
		outputList = append(outputList, output)
	}
	return outputList, nil
}

// RunCommands 批量下发命令
func (sw *Switch) RunCommands(cmds ...string) (string, error) {
	outputList, err := sw.writeChannel(cmds...)

	if err != nil {
		sw.Logger.WithFields(logFields).Error("命令执行错误")
		return "", err
	}

	output := ""
	for _, tempStr := range outputList {
		output += tempStr
	}

	// 保存日志
	err = sw.saveLogToFile()
	if err != nil {
		sw.Logger.WithFields(logFields).Errorf("日志保存失败%s", err)

	}

	return output, err
}

func (sw *Switch) saveLogToFile() error {
	sw.Logger.WithFields(logFields).Debug("[begin]保存至文件")
	path := "log/" + workTime.Format("2006-01-02")
	//fileName := path + "/" + workTime.Format("2006-01-02-150405") + sw.ip + ".log"
	fileName := path + "/" + sw.ip + "_" + workTime.Format("2006-01-02-150405") + ".log"
	tempFile, err := os.OpenFile(fileName,
		os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		sw.Logger.WithFields(logFields).Errorf("[end|error]日志文件打开失败.%s", err)
		return err
	}
	defer tempFile.Close()
	_, err = tempFile.WriteString(sw.OutLog)
	if err != nil {
		sw.Logger.WithFields(logFields).Errorf("[end|error]日志文件写入失败")
		return err
	}

	return nil
}
