package rSwitch

import (
	"golang.org/x/crypto/ssh"
	"net"
	"strings"
	"time"
)

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
}

// NewSwitchConnect 创建新会话
func NewSwitchConnect(ip, port, username, password string) (*Switch, error) {
	LogDebug("<NewSwitchConnect()>[begin]设备连接成功")
	//sw := new(Switch)
	//sw.ip = ip
	//sw.port = port
	//sw.username = username
	//sw.password = password

	sw := Switch{
		ip:       ip,
		port:     port,
		username: username,
		password: password,
	}

	// 创建客户端会话
	if err := sw.createClientSession(); err != nil {
		LogError("<createClientSession()>创建客户端会话失败.%s", err.Error())
		return nil, err
	}

	// 绑定pty连接，初始化管道
	if err := sw.connectPty(); err != nil {
		LogError("<connectPty()>pty、管道绑定失败.%s", err.Error())
		return nil, err
	}

	// 连接设备
	if err := sw.startShell(); err != nil {
		LogError("startShell()>连接远端设备失败.%s", err.Error())
		return nil, err
	}

	// 取消回显分页
	if err := sw.setScreenLength(); err != nil {
		LogError("startShell()>取消回显分页失败.%s", err.Error())
		return nil, err
	}

	sw.lastUseTime = time.Now() //修改设备登录时间
	LogDebug("<NewSwitchConnect()>[end]设备连接成功")

	return &sw, nil

}

// createClientSession 创建客户端会话
/*
@Description 创建客户端会话
@return 执行错误
*/
func (sw *Switch) createClientSession() error {
	LogDebug("<createClientSession()>[begin]初始化设备参数.([new] config ssh.ClientConfig)")
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
	LogDebug("<createClientSession()>[end]初始化设备参数.([new] config ssh.ClientConfig)")

	// 创建客户端
	LogDebug("<createClientSession()>[begin]创建并配置客户端.([new] client ssh.Dial())")
	client, err := ssh.Dial("tcp", sw.ip+":"+sw.port, &config)
	if err != nil {
		LogError("createClientSession()>[error]创建客户端失败.%s", err.Error())
		return err

	}
	LogDebug("<createClientSession()>[end]创建并配置客户端成功.([new] client ssh.Dial())")

	// 创建会话
	LogDebug("<createClientSession()>[begin]客户端建立新会话.([new] Session client.NewSession())")
	session, err := client.NewSession()
	if err != nil {
		LogError("createClientSession()>[error]创建会话失败.%s", err.Error())
		return err
	}
	LogDebug("<createClientSession()>[end]客户端建立新会话成功.([new] Session client.NewSession())")
	sw.session = session

	return nil
}

// 客户端会话绑定远程连接，初始化输入&接收管道
func (sw *Switch) connectPty() error {
	LogDebug("<connectVty()>[begin]绑定远程连接 初始化输入、输出管道.")
	defer func() {
		if err := recover(); err != nil {
			LogError("SSHSession muxShell err:%s", err)
		}
	}()

	// 初始化终端模式
	modes := ssh.TerminalModes{
		ssh.ECHO:          1,     //disable echoing
		ssh.TTY_OP_ISPEED: 14400, // input speed = 14.4k baud
		ssh.TTY_OP_OSPEED: 14400, // output speed = 14.4k baud
	}

	LogDebug("<connectVty()>[begin]远程会话连接.([run] Session session.RequestPty())")
	if err := sw.session.RequestPty("vt100", 80, 40, modes); err != nil {
		LogError("<connectVty()>[error]远程会话连接失败.([run] Session session.RequestPty())")
		return err
	}
	LogDebug("<connectVty()>[end]远程会话成功.([run] Session session.RequestPty())")

	LogDebug("<connectVty()>[begin]初始化输入管道.([run]session.StdinPipe())")
	write, err := sw.session.StdinPipe()
	if err != nil {
		LogDebug("<connectVty()>[error]初始化输入管道.([run]session.StdinPipe())")
	}
	LogDebug("<connectVty()>[end]初始化输入管道.([run]session.StdinPipe())")

	LogDebug("<connectVty()>[begin]初始化接收管道.([run]session.StdoutPipe())")
	read, err := sw.session.StdoutPipe()
	if err != nil {
		LogDebug("<connectVty()>[error]初始化接收管道.([run]session.StdoutPipe())")
	}
	LogDebug("<connectVty()>[end]初始化接收管道.([run]session.StdoutPipe())")

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
				LogError("<connectVty()>[error]远程会话pty写入失败.%s", err)
			}
		}()
		for cmd := range sw.inChan {
			_, err := write.Write([]byte(cmd + "\n"))
			if err != nil {
				LogDebug("<connectVty()>[error]远程会话pty写入失败.%s", err.Error())
				return
			}
		}
	}()

	//接收通道
	go func() {
		defer func() {
			if err := recover(); err != nil {
				LogDebug("<connectVty()>[error]远程会话pty读取失败.%s", err)
			}
		}()
		var (
			buf [65 * 1024]byte
			t   int
		)
		for {
			n, err := read.Read(buf[t:])
			if err != nil {
				LogDebug("<connectVty()>[error]远程会话pty读取失败.%s", err.Error())
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

	LogDebug("<connectVty()>[end]绑定远程连接 初始化输入、输出管道成功.")
	return nil

}

// 连接远程设备
func (sw *Switch) startShell() error {
	LogDebug("<start()>[begin]连接设备.")
	if err := sw.session.Shell(); err != nil {
		LogError("<start()>[error]连接设备失败.%s", err.Error())
		return err
	}
	LogDebug("<start()>[end]连接成功.")
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
	LogDebug("<readChannel()>[begin]读取管道内数据.")
	output := ""
	littleSleep := time.Millisecond * 10
	tempTimes := time.Millisecond // 睡的次数

getNowData:
	for {
		LogDebug("<readChannel()>[sleep]等待10毫秒")
		time.Sleep(littleSleep) // 睡10毫秒
		tempTimes += littleSleep
		//当前通道内容
		select {
		case newData, ok := <-sw.outChan:
			if !ok {
				// 通道关闭停止读取
				LogDebug("<readChannel()>[end|error]接收通道关闭")
				sw.OutLog += output
				return output
			}
			output += newData

		default:
			// 判断是否超时
			if tempTimes > timeout {
				LogDebug("<readChannel()>[end|timeout]读取管道内数据成功.")
				break getNowData

			}
			// 判断结尾字符是否符合要求
			for _, expect := range expects {
				if strings.Contains(output, expect) {
					LogDebug("<readChannel()>[end|success]读取管道内数据成功.")
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
	LogDebug("<writeChannel()>[begin]cmds:%v", cmds)
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
		LogError("命令执行错误")
		return "", err

	}

	output := ""
	for _, tempStr := range outputList {
		output += tempStr
	}

	return output, err
}
