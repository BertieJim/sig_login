//
//  siguseradd.cpp
//  zmqserver
//
//  Created by Bertie on 17/4/6.
//  Copyright (c) 2017年 Bertie. All rights reserved.
#include <stdlib.h>
#include <stdio.h>
#include <security/pam_appl.h>
#include <security/pam_misc.h>
#include <iostream>
#include <sys/ioctl.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <sys/types.h>
#include <pwd.h>
#include <thrift/protocol/TBinaryProtocol.h>
#include <thrift/transport/TSocket.h>
#include <thrift/transport/TTransportUtils.h>
#include <vector>
#include "gen-cpp/HandWriter.h"
#include "signatures.pb.h"
#include <zmq.hpp>
using namespace std;
using namespace pm_m;
using namespace apache::thrift;
using namespace apache::thrift::protocol;
using namespace apache::thrift::transport;

static struct pam_conv conv = {
    misc_conv,
    NULL 
};
int main(int argc,char *argv[])
{
    pam_handle_t *pamh=NULL;
    int retval;
    const char *user="nobody";
    if(argc == 2) {
        user = argv[1];
    }
    if(argc > 2||argc <2) {
        fprintf(stderr, "Usage: check_user [username]\n");
        exit(1);
    }
    
    retval = pam_start("siguseradd", user, &conv, &pamh);
    if (retval == PAM_SUCCESS)
        retval = pam_authenticate(pamh, 0);    /* is user really user? */
    if (retval == PAM_SUCCESS)
        retval = pam_acct_mgmt(pamh, 0);       /* permitted access? */
    /* This is where we have been authorized or not. */
    if (retval == PAM_SUCCESS) {
        fprintf(stdout, "->Authenticated SUCCESS\n");

        struct ifreq ifreq;
        int sock = 0;
        char mac[32] = "";
        sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) {
            perror("error sock");
            return 2;
        }
        strcpy(ifreq.ifr_name, "eth0");
        if (ioctl(sock, SIOCGIFHWADDR, &ifreq) < 0) {
            perror("error ioctl");
            return 3;
        }

        int i = 0;
        for (i = 0; i < 6; i++) {
            sprintf(mac + 3 * i, "%02X:", (unsigned char) ifreq.ifr_hwaddr.sa_data[i]);
        }
        mac[strlen(mac) - 1] = 0;

        char *username = (char *) malloc(strlen(mac) + strlen(user) + 2);
        strcpy(username, mac);
        strcat(username, ":");
        strcat(username, user);
        //printf("%s\n",username);


        const char *homedir;
        if ((homedir = getenv("HOME")) == NULL) {
            homedir = getpwuid(getuid())->pw_dir;
        }
        char *filepath = (char *) malloc(strlen(homedir) + 20);
        strcpy(filepath, homedir);
        strcat(filepath, "/.siguseradd");

        char input[100];
        FILE *fp;
        fp = fopen(filepath, "r");
        bool successfile = false;
        if (fp != NULL) {
            while (!feof(fp)) {
                fscanf(fp, "%s", input);
                if (!strcmp(input, user))//相等
                {
                    successfile = true;
                    printf("->\n%s Already register,Do you want to register again?Y/n:", user);
                    char t;
                    scanf("%c", &t);
                    if (t != 'Y' && t != 'y') {
                        if (pam_end(pamh, retval) != PAM_SUCCESS) {
                            pamh = NULL;
                            /* close Linux-PAM */
                            fprintf(stderr, "->check_user: failed to release authenticator\n");
                            exit(1);
                        }
                        return 0;       /* indicate success */
                    }
                    break;
                }
            }
            if (!successfile) {
                fp = fopen(filepath, "a");
                fprintf(fp, "%s\n", user);
                printf("->Changed file %s\n", filepath);
                successfile = true;
            }

        } else {
            fp = fopen(filepath, "w+");
            if (fp == NULL)
                exit(1);
            fprintf(fp, "%s\n", user);
            printf("->Created file %s\n", filepath);

        }
        fclose(fp);

        //接下来 要进行注册咯
        printf("\n->Now Start Register<-\n\n");

        //1.token 接受 sig序列 一共5个
        //2.将序列发送至 server 这里用thrift
        //3.得到是否注册成功 信号
        char ip[16] = "192.168.161.144";
        char port[5] = "1234";
        char token[7];
        Signatures sigs;

        //产生IP地址和端口号:
        zmq::context_t context(1);
        zmq::socket_t socket(context, ZMQ_REP);
        socket.bind("tcp://*:1234");

        bool if_exit_login = false;
        bool get_right_token = false;
        printf("->Please open device,input IP and PORT:\n");
        printf("---IP   :%s\n---PORT :%s\n", ip, port);
        bool register_ret = false;

        while (!if_exit_login) {
            //产生口令
            srand((int) time(NULL));     //每次执行种子不同，生成不同的随机数
            for (int i = 0; i < 6; i++) {
                token[i] = '0' + rand() % 10;
            }
            token[6] = '\0';
            printf("->Please open device,input TOKEN:\n");
            printf("---TOKEN:%s\n", token);
            cout << "->Wait Data...\n";

            zmq::message_t request2;
            zmq::message_t reply;
            socket.recv(&request2);
            opensv::Request request;
            request.id = 115;
            vector <opensv::Signature> t_signatures;
            //get and extract signatures
            sigs.ParseFromArray(request2.data(), (int) request2.size());
            if (sigs.id() == token) {
                get_right_token = true;
                printf("->GET DATA...\n");
                printf("\n->Register...\n");
            }
            if (!get_right_token) {
                char ch;
                printf("->Wrong Token\n");
                printf("->Do you want to try again?(Y/n):");
                scanf("%c", &ch);
                getchar();//去掉换行符
                if (ch != 'Y' && ch != 'y') {
                    if_exit_login = true;
                    continue;
                } else {
                    continue;
                }
            }
            for (int i = 0; i < sigs.signatures_size() && get_right_token; i++) {
                opensv::Signature t_signature;
                vector <opensv::Point> t_points;
                Signature sig1 = sigs.signatures(i);
                for (int j = 0; j < sig1.points_size(); j++) {
                    opensv::Point t_point;
                    Point p1 = sig1.points(j);
                    t_point.t = p1.t();
                    t_point.x = p1.x();
                    t_point.y = p1.y();
                    t_point.p = p1.p();
                  //  cout<<t_point.t<<" "<<t_point.x<<" "<<t_point.y<<" "<<t_point.p<<" "<<endl;
                    t_points.push_back(t_point);
                    //cout<<p1.t()<<"b";
                }
                t_signature.points = t_points;
                t_signatures.push_back(t_signature);
            }
            request.signatures = t_signatures;
            //cout<<"SIZE"<<sigs.signatures_size()<<"\n";

            //  Send reply back to client
            memcpy(reply.data(), "GET", 3);
            socket.send(reply);

            //send data to server now
            boost::shared_ptr<TTransport> socket(new TSocket("192.168.161.142", 9090));
            boost::shared_ptr<TTransport> transport(new TBufferedTransport(socket));
            boost::shared_ptr<TProtocol> protocol(new TBinaryProtocol(transport));
            opensv::HandWriterClient client(protocol);
            opensv::Ret ret;

            try {
                transport->open();
                client.accountRegister(ret, request);

            } catch (TException &tx) {
                cout << "Error: " << tx.what() << endl;
            }

            register_ret = ret.success;
            if (!register_ret) {

                char ch;
                printf("->Regester FAIL\nPlease do more Comlicated Sig\n");
                printf("\n->Do you want to try again?(Y/n):");
                scanf("%c", &ch);
                getchar();//去掉换行符
                if (ch != 'Y' && ch != 'y') {
                    if_exit_login = true;
                    continue;
                } else {
                    continue;
                }
            } else {
                if_exit_login = true;
            }

        }
        if(register_ret)
        {
            printf("->Register SUCCESS!\n");
            fprintf(stdout, "\n->User ADD SUCCESS\n\n");
        }


    } else {
        fprintf(stdout, "\n->Not Authenticated\n");
    }
    if (pam_end(pamh,retval) != PAM_SUCCESS) {
        pamh = NULL;
        /* close Linux-PAM */
        fprintf(stderr, "check_user: failed to release authenticator\n");
        exit(1); }
    return ( retval == PAM_SUCCESS ? 0:1 );       /* indicate success */

}
