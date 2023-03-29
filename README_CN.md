# go-clamav
[![GoDoc](https://pkg.go.dev/badge/github.com/ca110us/go-clamav?status.svg)](https://pkg.go.dev/github.com/ca110us/go-clamav?tab=doc)

go-clamav 是 go 语言对 [libclamav](https://docs.clamav.net/manual/Development/libclamav.html) 的封装

## 环境
### Ubuntu 20.04 

```bash
apt-get update && apt-get install -y \
  gcc make pkg-config python3 python3-pip python3-pytest valgrind \
  check libbz2-dev libcurl4-openssl-dev libjson-c-dev libmilter-dev \
  libncurses5-dev libpcre2-dev libssl-dev libxml2-dev zlib1g-dev
  python3 -m pip install --user cmake / apt-get install cmake
```


### 静态编译
```bash
$ cd example  
$ sudo bash prepare.sh
$ SRCDIR=$(pwd)
$ export CGO_CFLAGS="-g -Wall -I${SRCDIR}/clamav-mussels-cookbook/mussels/install/include"
$ export CGO_LDFLAGS="-L${SRCDIR}/clamav-mussels-cookbook/mussels/install/lib -lclamav_static -lbz2_static -lclammspack_static -lclamunrar_iface_static -lclamunrar_static -lcrypto -ljson-c -lpcre2-8 -lpcre2-posix -lssl -lxml2 -lz -lm -ldl -lstdc++"
$ CGO_ENABLED=1 go build -ldflags '-linkmode external -extldflags "-static"' -o go-clamav main.go


```

###  Usage
```bash
$ ./go-clamav --hlep
flag provided but not defined: -hlep
Usage of ./go-clamav:
  -cpu int
    	the maximum number of CPUs to use 10-100 (default 10)
  -dir string
    	the directory to scan
  -file string
    	the file to scan
  -scan_recu uint
    	the maximum recursion depth for directory scanning default 5 max 20 (default 5)


$ Scan File 
$ ./go-clamav --file=/etc/passwd
db load succeed: 9912
chan string count 1
Scan completed.
costTime 1.516261496s

$ ./go-clamav --dir=/www
db load succeed: 9912
chan string count 2
209 YARA.Unix_Packer_UpxDetail.UNOFFICIAL Virus(es) detected ../test_file/dd/nmap
209 YARA.Unix_Packer_UpxDetail.UNOFFICIAL Virus(es) detected ../test_file/nmap
Scan completed.
costTime 14.905588934s


The default limit is 10% of the overall CPU if you want to open the CPU. Use the following:
$ ./go-clamav --dir=../test_file --cpu=80
db load succeed: 9912
chan string count 2
209 YARA.Unix_Packer_UpxDetail.UNOFFICIAL Virus(es) detected ../test_file/dd/nmap
209 YARA.Unix_Packer_UpxDetail.UNOFFICIAL Virus(es) detected ../test_file/nmap
Scan completed.
costTime 6.38549549s

The default scan directory level is 5 times. If you want to scan multiple layers. As follows:
$ ./go-clamav --dir=../test_file --cpu=80  --scan_recu=10
db load succeed: 9912
chan string count 2
209 YARA.Unix_Packer_UpxDetail.UNOFFICIAL Virus(es) detected ../test_file/dd/nmap
209 YARA.Unix_Packer_UpxDetail.UNOFFICIAL Virus(es) detected ../test_file/nmap
Scan completed.
costTime 6.38549549s
```


## 参考
[ca110us/go-clamav](https://github.com/ca110us/go-clamav)
