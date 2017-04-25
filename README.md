# sig_login
use signatures log in Linux(Ubuntu) instead plain password
---------------------
本产品测试于Unbuntu14.04LTS
---------------------
需要安装protobuf 3.1.0
        zmq-c 3.2.5
		thrift 0.10.0
以上均到官网下载
----------------------
1.编译protobuf
 protoc --java_out=. signatures.proto
 protoc --cpp_out=. signatures.proto
2.编译thrift
  thrift --gen cpp pm_m.thrift
3.下载PAM
  sudo apt-get install libpam0g-dev
5.安装ZMQ-C++
cp zmq.hpp /usr/local/include/zmq.hpp 
-----------------------------------------
编译命令
1.编译siguseradd
g++ siguseradd.cpp signatures.pb.cc gen-cpp/* -o siguseradd -lpam -lpam_misc -lthrift -lzmq -lprotobuf
2.编译PAM并安装
见comiplepam.sh
3.修改login 配置文件
见patch
----------------------------------------
本产品需要结合android input和server使用
别忘了改bind IP 和port
