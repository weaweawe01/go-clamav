package main

import (
	"fmt"
	clamav "github.com/weaweawe01/go-clamav"
	"os"
	"path/filepath"
)

func main() {
	//判断args 参数
	if len(os.Args) < 2 {
		fmt.Println("Usage: clamav file or dir")
		os.Exit(1)
	}
	//获取参数
	file := os.Args[1]
	//判断这个是文件还是目录
	fi, err := os.Stat(file)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	var flag bool
	//如果是文件
	if fi.Mode().IsRegular() {
		//表示文件
		flag=true
	}	else if fi.Mode().IsDir() {

		//表示目录
		flag=false
	} else {
		fmt.Println("Usage: clamav file or dir")
		os.Exit(1)
	}

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

	c.EngineSetNum(clamav.CL_ENGINE_MAX_SCANSIZE, 1024*1024*40)
	c.EngineSetNum(clamav.CL_ENGINE_MAX_SCANTIME, 9000)
	// fmt.Println(c.EngineGetNum(clamav.CL_ENGINE_MAX_SCANSIZE))

	// scan
	//如果file 参数不为空，则检查文件是否存在。然后进行扫描
	if flag{
		// scan file
		scanned, virusName, ret := c.ScanFile(file)
		fmt.Println(scanned, virusName, ret)
	}else{
		//遍历所有文件
		err = filepath.Walk(file, func(path string, info os.FileInfo, err error) error {
			if info.IsDir() {
				return nil
			}
			// scan file
			fmt.Println("scan file:", path)
			scanned, virusName, ret := c.ScanFile(path)
			fmt.Println(scanned, virusName, ret)
			return nil
		})
	}
}
