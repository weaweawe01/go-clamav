# go-clamav
[![GoDoc](https://pkg.go.dev/badge/github.com/ca110us/go-clamav?status.svg)](https://pkg.go.dev/github.com/ca110us/go-clamav?tab=doc)

go-clamav is go wrapper for [libclamav](https://docs.clamav.net/manual/Development/libclamav.html)

## Environment
### Ubuntu 20.04

```bash
apt-get update && apt-get install -y \
  gcc make pkg-config python3 python3-pip python3-pytest valgrind \
  check libbz2-dev libcurl4-openssl-dev libjson-c-dev libmilter-dev \
  libncurses5-dev libpcre2-dev libssl-dev libxml2-dev zlib1g-dev
  python3 -m pip install --user cmake / apt-get install cmake
```


### Static build
```bash
$ sudo bash ./prepare.sh
$ SRCDIR=$(pwd)
$ export CGO_CFLAGS="-g -Wall -I${SRCDIR}/clamav-mussels-cookbook/mussels/install/include"
$ export CGO_LDFLAGS="-L${SRCDIR}/clamav-mussels-cookbook/mussels/install/lib -lclamav_static -lbz2_static -lclammspack_static -lclamunrar_iface_static -lclamunrar_static -lcrypto -ljson-c -lpcre2-8 -lpcre2-posix -lssl -lxml2 -lz -lm -ldl -lstdc++"
$ CGO_ENABLED=1 go build -ldflags '-linkmode external -extldflags "-static"' -o output_binary main.go


Scan File
$ ./go-clamav test_file/nmap 
db load succeed: 9912
209 YARA.Unix_Packer_UpxDetail.UNOFFICIAL Virus(es) detected


Scan Dir 
$ ./go-clamav test_file 
db load succeed: 9912
209 YARA.Unix_Packer_UpxDetail.UNOFFICIAL Virus(es) detected
```

## Reference
[ca110us/go-clamav](https://github.com/ca110us/go-clamav)

