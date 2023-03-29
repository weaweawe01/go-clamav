package main

import (
	"flag"
	"fmt"
	clamav "github.com/weaweawe01/go-clamav"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)
//获取CPU核心数量



func main() {
	//判断args 参数
	// 定义命令行参数变量
	filePtr := flag.String("file", "", "the file to scan")
	dirPtr := flag.String("dir", "", "the directory to scan")
	cpuPtr := flag.Int("cpu", 10, "the maximum number of CPUs to use 10-100")
	scanRecuPtr := flag.Uint64("scan_recu", 5, "the maximum recursion depth for directory scanning default 5 max 20")


	// 解析命令行参数
	flag.Parse()

	// 获取参数值
	file := *filePtr
	dir := *dirPtr
	cpu := *cpuPtr
	scanRecu := *scanRecuPtr
	//开始时间
	startTime := time.Now()
	//写一个cgroups 限制CPU 函数
	pid := os.Getpid()
	//创建一个新的cgroup，限制当前进程使用10%的CPU资源
	control, err := createCgroupWithCPULimit(pid, cpu)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
	//确保在程序结束时删除cgroup
	defer control.Delete()

	//获取参数
	//file := os.Args[1]
	//判断这个是文件还是目录
	var flags bool

	// 文件和目录都没有输入的时候
	if file == "" && dir == "" {
		fmt.Println("file and dir is empty")
		//展示帮助

		os.Exit(1)
	}

	// 文件和目录只能选择一个
	if file != "" && dir != "" {
		fmt.Println("file and dir can only choose one")
		os.Exit(1)
	}

	if file!=""{
		_, err := os.Stat(file)
		if err != nil {
			fmt.Println("file not found")
			os.Exit(1)
		}
		flags=true

	}else if dir!=""{
		_, err := os.Stat(dir)
		if err != nil {
			fmt.Println("dir not found")
			os.Exit(1)
		}
		flags=false
		file=dir
	}else{
		fmt.Println("file or dir not found")
		os.Exit(1)
	}
	//建立一个扫描队列 用于存放需要扫描的文件
	fileChan := make(chan string,1024 * 1024 * 10)
	//defer close(fileChan)
	var wg sync.WaitGroup
	wg.Add(1)
	c := new(clamav.Clamav)
	err = c.Init(clamav.SCAN_OPTIONS{
		General:   0,
		Parse:     clamav.CL_SCAN_PARSE_ARCHIVE | clamav.CL_SCAN_PARSE_ELF,
		Heuristic: 0,
		Mail:      0,
		Dev:       0,
	})
	if err != nil {
		fmt.Println("err1",err)
		return
	}
	// free clamav memory
	defer c.Free()
	// load db
	signo, err := c.LoadDB("./db", uint(clamav.CL_DB_DIRECTORY))
	if err != nil {
		fmt.Println("err2",err)
		return
	}
	fmt.Println("db load succeed:", signo)
	// compile engine
	err = c.CompileEngine()
	if err != nil {
		fmt.Println("err3",err)
		return
	}
	//最大扫描数据大小
	c.EngineSetNum(clamav.CL_ENGINE_MAX_SCANSIZE, 1024 * 1024 * 18)
	//可扫描的最大文件大小
	c.EngineSetNum(clamav.CL_ENGINE_MAX_FILESIZE, 1024 * 1024 * 10)

	//最大扫描时间
	c.EngineSetNum(clamav.CL_ENGINE_MAX_SCANTIME, 5000)
	//设置最大的文件数量
	c.EngineSetNum(clamav.CL_ENGINE_MAX_FILES, 1000*10*10)
	//设置最大的递归深度
	c.EngineSetNum(clamav.CL_ENGINE_MAX_RECURSION, scanRecu)

	go func(flags bool,file_path string) {
		defer wg.Done()
		defer close(fileChan)
		if flags {
			// scan file
			fileInfo, err := os.Stat(file_path)
			if err != nil {
				return
			}
			if fileInfo.Mode()&os.ModeSymlink != 0{
				return
			}
			if fileInfo.Mode()&os.ModeDevice != 0{
				return
			}
			if fileInfo.Mode().IsRegular() {
				fileChan <- file_path
			}

		}else {
			walk(int(scanRecu),file_path, 0, func(path string, info os.FileInfo, err error) error {
				if err != nil {

					return nil
				}
				if info.IsDir() {
					return nil
				}
				if info.Mode()&os.ModeSymlink != 0{
					return nil
				}
				if info.Mode()&os.ModeDevice != 0{
					return nil
				}
				if info.Size()<10{
					return  nil
				}
				ext := strings.ToLower(filepath.Ext(path))
				if _, ok := SKIP_SUFFIX[ext]; ok {
					return nil
				}
				if SCAN_DIR_FILTER[path] {
					return filepath.SkipDir
				}
				if len(fileChan) >= 1024 * 1024 * 10 {
					//退出当前线程
					runtime.Goexit()
				}
				fileChan <- path
				return nil
			})
		}
	}(flags,file)
	wg.Wait()
	fileChanLen := len(fileChan)
	fmt.Println("通道内多少長度",fileChanLen)
	time.Sleep(time.Millisecond*500)

	wg.Add(1)
	go func() {
		defer wg.Done()
		for path := range fileChan {
			wg.Add(1)
			go func(path string) {
				defer wg.Done()
				scanned, virusName, ret := c.ScanFile(path)
				if virusName!= "" {
					fmt.Println(scanned, virusName, ret,path)
				}
			}(path)
		}
	}()
	wg.Wait()
	//获取通道中的长度
	fmt.Println("Scan completed.")
	//结束时间
	endTime := time.Now()
	//计算耗时
	costTime := endTime.Sub(startTime)
	fmt.Println("costTime",costTime)
}
