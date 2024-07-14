package main

import (
	"fmt"
	"os"
	"runtime"
	"time"
)

func main() {
	go (func() {
		//调用 LockOSThread 将 绑定 当前 goroutine 到当前 操作系统线程``，此 goroutine 将始终在此线程执行，
		//其它 goroutine 则无法在此线程中得到执行，
		//直到当前调用线程执行了 UnlockOSThread 为止（也就是说指定一个goroutine 独占 一个系统线程）；

		runtime.LockOSThread()
		fmt.Println(1, time.Now())
		fmt.Println(os.Getpid())
		time.Sleep(time.Second * 5)
	})()
	time.Sleep(time.Second)
	fmt.Println(2, time.Now())
	fmt.Println(os.Getpid())
}
