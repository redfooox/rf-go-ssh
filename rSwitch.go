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

func (sw *Switch) init() {
	// 初始化日志文件夹
	path := "log/" + time.Now().Format("2006-01-02")
	err := os.MkdirAll(path, 777)
	if err != nil {
		// 初始化目录失败
		println("初始化目录失败")
	} else {
		println(path, "[log/<time>]已存在/创建成功")
	}

	logFile, err := os.OpenFile("log/r.log",
		os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalln("打开日志文件失败:", err)
	}

	sw.Logger = log.New()

	// 设置将日志输出到标准输出（默认的输出为stderr，标准错误）
	// 日志消息输出可以是任意的io.writer类型
	sw.Logger.SetOutput(io.MultiWriter(logFile, os.Stdout))
	// 设置日志级别为warn以上
	sw.Logger.SetLevel(log.WarnLevel)
	//sw.Logger.SetLevel(log.DebugLevel)
	// 为当前logrus实例设置消息输出格式为text格式。
	// 同样地，也可以单独为某个logrus实例设置日志级别和hook，这里不详细叙述。
	sw.Logger.Formatter = &log.TextFormatter{}

	sw.Logger.WithFields(log.Fields{
		"ip":       sw.ip,
		"username": sw.username,
	}).Error("test")
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
	log.Println("<NewSwitchConnect()>[begin]设备连接成功")

	sw := Switch{
		ip:       ip,
		port:     port,
		username: username,
		password: password,
	}
	// 初始化日志等
	sw.init()
	sw.Logger.WithFields(log.Fields{
		"ip":       sw.ip,
		"username": sw.username,
	}).Error("这是一个错误")

	// 创建客户端会话
	if err := sw.createClientSession(); err != nil {
		sw.Logger.WithFields(log.Fields{
			"ip":       sw.ip,
			"username": sw.username,
		}).Errorf("<createClientSession()>创建客户端会话失败.%s", err.Error())
		return nil, err
	}

	// 绑定pty连接，初始化管道
	if err := sw.connectPty(); err != nil {
		sw.Logger.WithFields(log.Fields{
			"ip":       sw.ip,
			"username": sw.username,
		}).Printf("<connectPty()>pty、管道绑定失败.%s", err.Error())
		return nil, err
	}

	// 连接设备
	if err := sw.startShell(); err != nil {
		sw.Logger.WithFields(log.Fields{
			"ip":       sw.ip,
			"username": sw.username,
		}).Printf("startShell()>连接远端设备失败.%s", err.Error())
		return nil, err
	}

	// 取消回显分页
	if err := sw.setScreenLength(); err != nil {
		sw.Logger.WithFields(log.Fields{
			"ip":       sw.ip,
			"username": sw.username,
		}).Printf("startShell()>取消回显分页失败.%s", err.Error())
		return nil, err
	}

	sw.lastUseTime = time.Now() //修改设备登录时间
	sw.Logger.WithFields(log.Fields{
		"ip":       sw.ip,
		"username": sw.username,
	}).Println("<NewSwitchConnect()>[end]设备连接成功")

	return &sw, nil

}

// createClientSession 创建客户端会话
/*
@Description 创建客户端会话
@return 执行错误
*/
func (sw *Switch) createClientSession() error {
	sw.Logger.WithFields(log.Fields{
		"ip":       sw.ip,
		"username": sw.username,
	}).Debug("<createClientSession()>[begin]初始化设备参数.([new] config ssh.ClientConfig)")
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
	sw.Logger.WithFields(log.Fields{
		"ip":       sw.ip,
		"username": sw.username,
	}).Debug("<createClientSession()>[end]初始化设备参数.([new] config ssh.ClientConfig)")

	// 创建客户端
	sw.Logger.WithFields(log.Fields{
		"ip":       sw.ip,
		"username": sw.username,
	}).Debug("<createClientSession()>[begin]创建并配置客户端.([new] client ssh.Dial())")
	client, err := ssh.Dial("tcp", sw.ip+":"+sw.port, &config)
	if err != nil {
		sw.Logger.WithFields(log.Fields{
			"ip":       sw.ip,
			"username": sw.username,
		}).Errorf("createClientSession()>[error]创建客户端失败.%s", err.Error())
		return err

	}
	sw.Logger.WithFields(log.Fields{
		"ip":       sw.ip,
		"username": sw.username,
	}).Debug("<createClientSession()>[end]创建并配置客户端成功.([new] client ssh.Dial())")

	// 创建会话
	sw.Logger.WithFields(log.Fields{
		"ip":       sw.ip,
		"username": sw.username,
	}).Debug("<createClientSession()>[begin]客户端建立新会话.([new] Session client.NewSession())")
	session, err := client.NewSession()
	if err != nil {
		sw.Logger.WithFields(log.Fields{
			"ip":       sw.ip,
			"username": sw.username,
		}).Errorf("createClientSession()>[error]创建会话失败.%s", err.Error())
		return err
	}
	sw.Logger.WithFields(log.Fields{
		"ip":       sw.ip,
		"username": sw.username,
	}).Debug("<createClientSession()>[end]客户端建立新会话成功.([new] Session client.NewSession())")
	sw.session = session

	return nil
}

// 客户端会话绑定远程连接，初始化输入&接收管道
func (sw *Switch) connectPty() error {
	sw.Logger.WithFields(log.Fields{
		"ip":       sw.ip,
		"username": sw.username,
	}).Debug("<connectVty()>[begin]绑定远程连接 初始化输入、输出管道.")
	defer func() {
		if err := recover(); err != nil {
			sw.Logger.WithFields(log.Fields{
				"ip":       sw.ip,
				"username": sw.username,
			}).Errorf("SSHSession muxShell err:%s", err)
		}
	}()

	// 初始化终端模式
	modes := ssh.TerminalModes{
		ssh.ECHO:          1,     //disable echoing
		ssh.TTY_OP_ISPEED: 14400, // input speed = 14.4k baud
		ssh.TTY_OP_OSPEED: 14400, // output speed = 14.4k baud
	}

	sw.Logger.WithFields(log.Fields{
		"ip":       sw.ip,
		"username": sw.username,
	}).Debug("<connectVty()>[begin]远程会话连接.([run] Session session.RequestPty())")
	if err := sw.session.RequestPty("vt100", 80, 40, modes); err != nil {
		sw.Logger.WithFields(log.Fields{
			"ip":       sw.ip,
			"username": sw.username,
		}).Errorf("<connectVty()>[error]远程会话连接失败.([run] Session session.RequestPty())")
		return err
	}
	sw.Logger.WithFields(log.Fields{
		"ip":       sw.ip,
		"username": sw.username,
	}).Debug("<connectVty()>[end]远程会话成功.([run] Session session.RequestPty())")

	sw.Logger.WithFields(log.Fields{
		"ip":       sw.ip,
		"username": sw.username,
	}).Debug("<connectVty()>[begin]初始化输入管道.([run]session.StdinPipe())")
	write, err := sw.session.StdinPipe()
	if err != nil {
		sw.Logger.WithFields(log.Fields{
			"ip":       sw.ip,
			"username": sw.username,
		}).Debug("<connectVty()>[error]初始化输入管道.([run]session.StdinPipe())")
	}
	sw.Logger.WithFields(log.Fields{
		"ip":       sw.ip,
		"username": sw.username,
	}).Debug("<connectVty()>[end]初始化输入管道.([run]session.StdinPipe())")

	sw.Logger.WithFields(log.Fields{
		"ip":       sw.ip,
		"username": sw.username,
	}).Debug("<connectVty()>[begin]初始化接收管道.([run]session.StdoutPipe())")
	read, err := sw.session.StdoutPipe()
	if err != nil {
		sw.Logger.WithFields(log.Fields{
			"ip":       sw.ip,
			"username": sw.username,
		}).Debug("<connectVty()>[error]初始化接收管道.([run]session.StdoutPipe())")
	}
	sw.Logger.WithFields(log.Fields{
		"ip":       sw.ip,
		"username": sw.username,
	}).Debug("<connectVty()>[end]初始化接收管道.([run]session.StdoutPipe())")

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
				sw.Logger.WithFields(log.Fields{
					"ip":       sw.ip,
					"username": sw.username,
				}).Errorf("<connectVty()>[error]远程会话pty写入失败.%s", err)
			}
		}()
		for cmd := range sw.inChan {
			_, err := write.Write([]byte(cmd + "\n"))
			if err != nil {
				sw.Logger.WithFields(log.Fields{
					"ip":       sw.ip,
					"username": sw.username,
				}).Debugf("<connectVty()>[error]远程会话pty写入失败.%s", err.Error())
				return
			}
		}
	}()

	//接收通道
	go func() {
		defer func() {
			if err := recover(); err != nil {
				sw.Logger.WithFields(log.Fields{
					"ip":       sw.ip,
					"username": sw.username,
				}).Debugf("<connectVty()>[error]远程会话pty读取失败.%s", err)
			}
		}()
		var (
			buf [65 * 1024]byte
			t   int
		)
		for {
			n, err := read.Read(buf[t:])
			if err != nil {
				sw.Logger.WithFields(log.Fields{
					"ip":       sw.ip,
					"username": sw.username,
				}).Debugf("<connectVty()>[error]远程会话pty读取失败.%s", err.Error())
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

	sw.Logger.WithFields(log.Fields{
		"ip":       sw.ip,
		"username": sw.username,
	}).Debug("<connectVty()>[end]绑定远程连接 初始化输入、输出管道成功.")
	return nil

}

// 连接远程设备
func (sw *Switch) startShell() error {
	sw.Logger.WithFields(log.Fields{
		"ip":       sw.ip,
		"username": sw.username,
	}).Debug("<start()>[begin]连接设备.")
	if err := sw.session.Shell(); err != nil {
		sw.Logger.WithFields(log.Fields{
			"ip":       sw.ip,
			"username": sw.username,
		}).Errorf("<start()>[error]连接设备失败.%s", err.Error())
		return err
	}
	sw.Logger.WithFields(log.Fields{
		"ip":       sw.ip,
		"username": sw.username,
	}).Debug("<start()>[end]连接成功.")
	sw.readChannel(time.Second*5, ">", "]")
	return nil
}

// 取消回显分页
func (sw *Switch) setScreenLength() error {
	_, err := sw.RunCommands("screen-length 0 temporary")
	if err != nil {
		return err
	}

	return nil
}

// 读取接收管道内容
func (sw *Switch) readChannel(timeout time.Duration, expects ...string) string {
	sw.Logger.WithFields(log.Fields{
		"ip":       sw.ip,
		"username": sw.username,
	}).Debug("<readChannel()>[begin]读取管道内数据.")
	output := ""
	littleSleep := time.Millisecond * 10
	tempTimes := time.Millisecond // 睡的次数

getNowData:
	for {
		sw.Logger.WithFields(log.Fields{
			"ip":       sw.ip,
			"username": sw.username,
		}).Debug("<readChannel()>[sleep]等待10毫秒")
		time.Sleep(littleSleep) // 睡10毫秒
		tempTimes += littleSleep
		//当前通道内容
		select {
		case newData, ok := <-sw.outChan:
			if !ok {
				// 通道关闭停止读取
				sw.Logger.WithFields(log.Fields{
					"ip":       sw.ip,
					"username": sw.username,
				}).Debug("<readChannel()>[end|error]接收通道关闭")
				sw.OutLog += output
				return output
			}
			output += newData

		default:
			// 判断是否超时
			if tempTimes > timeout {
				sw.Logger.WithFields(log.Fields{
					"ip":       sw.ip,
					"username": sw.username,
				}).Debug("<readChannel()>[end|timeout]读取管道内数据成功.")
				break getNowData

			}
			// 判断结尾字符是否符合要求
			for _, expect := range expects {
				if strings.Contains(output, expect) {
					sw.Logger.WithFields(log.Fields{
						"ip":       sw.ip,
						"username": sw.username,
					}).Debug("<readChannel()>[end|success]读取管道内数据成功.")
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
	sw.Logger.WithFields(log.Fields{
		"ip":       sw.ip,
		"username": sw.username,
	}).Debugf("<writeChannel()>[begin]cmds:%v", cmds)
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
		sw.Logger.WithFields(log.Fields{
			"ip":       sw.ip,
			"username": sw.username,
		}).Error("命令执行错误")
		return "", err

	}

	output := ""
	for _, tempStr := range outputList {
		output += tempStr
	}

	return output, err
}
