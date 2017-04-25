#!/bin/sh
g++ -fPIC -DPIC -shared -rdynamic -o pam_kwe.so pam_kwe.cpp signatures.pb.cc gen-cpp/* -lzmq -lprotobuf -lthrift
sudo mv pam_kwe.so /lib/x86_64-linux-gnu/security/
sudo chown root:root /lib/x86_64-linux-gnu/security/pam_kwe.so 
sudo chmod 777 /lib/x86_64-linux-gnu/security/pam_kwe.so 

