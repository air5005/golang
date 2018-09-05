yum install go
yum install libpcap-devel.x86_64

export GOPATH=/home/ych/golang/autotestproj
go get github.com/google/gopacket

export LD_LIBRARY_PATH=/home/ych/zr9101/install/npa/lib
go build autotest.go
./autotest p4p1_0 /home/ych/pcap 1

