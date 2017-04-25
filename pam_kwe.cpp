/* Define which PAM interfaces we provide */
#define PAM_SM_ACCOUNT
#define PAM_SM_AUTH
#define PAM_SM_PASSWORD
#define PAM_SM_SESSION

/* Include PAM headers */
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <unistd.h>
#include <security/pam_misc.h>
#include <sys/ioctl.h>

#include <sys/types.h>
#include <pwd.h>
#include <stdio.h>
#include <string>
#include <unistd.h>
#include <iostream>
#include <stdlib.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <net/if.h>
#include <fcntl.h>
#include <signal.h>
#include "signatures.pb.h"
#include <zmq.hpp>
#include <thrift/protocol/TBinaryProtocol.h>
#include <thrift/transport/TSocket.h>
#include <thrift/transport/TTransportUtils.h>
#include <vector>
#include "gen-cpp/HandWriter.h"
using namespace std;
using namespace pm_m;
using namespace apache::thrift;
using namespace apache::thrift::protocol;
using namespace apache::thrift::transport;
time_t tstart;
time_t tend;
//bool timeisout = false;
//float timediff = 0;
bool end_t_connet_tread = false;
int try_times = 0;
#define N 5
char token[7];
bool getrighttoken = false;
bool getrightsigs = false;

//--两个线程，一个等待回答，一个计时
pthread_t t_timer[5];
pthread_t t_connet[5];
pthread_t t_timer2;
pthread_t t_connet2;
pthread_mutex_t mutex_R = PTHREAD_MUTEX_INITIALIZER ;
Signatures sigs;


void findIP(char *ip, int size)
{


}
void *f_timer2(void *)
{
    tstart =time(NULL);//or time(&start);
    printf("-------------------------------------\n");
    int timediff = 0;
    while(timediff < 35&&!end_t_connet_tread)
    {
        sleep(1);
        tend =time(NULL);//or time(&start);
        pthread_mutex_lock(&mutex_R);
        timediff = (int)difftime(tend,tstart);
        pthread_mutex_unlock(&mutex_R);
        printf("#");
        fflush(stdout);
    }
    printf("\n");
    sleep(1);

    if(!end_t_connet_tread)
    {
        cout<<"->Get Signature Failure...\n\n";
    }
    else
    {
        cout<<"->Get Signature Success\n";
    }

    return NULL;
}
void *f_connect2(void *cont)
{
    zmq::message_t request;
    zmq::message_t reply;

    zmq::socket_t *socket = (zmq::socket_t *)cont;
    socket->recv(&request);
    pthread_mutex_lock(&mutex_R);
    //get and extract signatures
    sigs.ParseFromArray(request.data(), (int)request.size());

    //cout<<endl<<sigs.id()<<"eeeeeee"<<endl;
  //  cout<<sigs.signatures(0).points(0).x()<<"b";
    //cout<<"a"<<sigs.signatures().size()<<endl;

    if(sigs.id()== token)
    {
        getrightsigs = true;
    }
    //  Send reply back to client
    memcpy (reply.data (), "GET", 3);
    socket->send (reply);

    end_t_connet_tread = true;

    pthread_mutex_unlock(&mutex_R);
    return NULL;
}
void *f_timer(void *)
{
    tstart =time(NULL);//or time(&start);
    printf("-------------------------------------\n");
    int timediff = 0;
    while(timediff < 35&&!end_t_connet_tread)
    {
        sleep(1);
        tend =time(NULL);//or time(&start);
        pthread_mutex_lock(&mutex_R);
        timediff = (int)difftime(tend,tstart);
        pthread_mutex_unlock(&mutex_R);

        printf("#");
        fflush(stdout);


    }
    printf("\n");
    sleep(1);
    if(!end_t_connet_tread)
    {
        cout<<"->Time is out...\n\n";
    }
    else
    {
        end_t_connet_tread = true;
        cout<<"->Connect success\n";
    }

    return NULL;
}
void *f_connect(void *cont)
{
    zmq::message_t request;
    zmq::socket_t *socket2 = (zmq::socket_t *)cont;
    socket2->recv(&request);
    pthread_mutex_lock(&mutex_R);
    //看看token正确吗 正确返回
    char * ret = (char*)malloc(request.size());
    memcpy(ret, request.data(), request.size());
    zmq::message_t reply (8);
    //必须要返回 才能结束 才能接收下一个recerive
    //关闭也不行

    if(!strcmp(ret, token))
    {
        char ret2[8] = "Y,";
        strcat(ret2, ret);
        //DEBUG
        //cout<<ret2<<endl;
        getrighttoken = true;
        memcpy (reply.data (), ret2, 8);
    }
    else
    {
        char ret2[8] = "N,";
        strcat(ret2, ret);
        getrighttoken = false;
        memcpy (reply.data (), ret2, 8);
    }

    socket2->send (reply);
    end_t_connet_tread = true;
    pthread_mutex_unlock(&mutex_R);
    return NULL;

}
/* PAM entry point for session creation */
int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return(PAM_SUCCESS);
}

/* PAM entry point for session cleanup */
int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return(PAM_SUCCESS);
}

/* PAM entry point for accounting */
int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return(PAM_SUCCESS);
}
//pam_sm_authenticate
/* PAM entry point for authentication verification */
int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    //检查下 该用户是否存在
    const char *user = NULL;
    int pgu_ret;
    pgu_ret = pam_get_user(pamh, &user, NULL);
    if (pgu_ret != PAM_SUCCESS || user == NULL) {
        return(PAM_IGNORE);
    }
    //see if has user
    const char *homedir;
    if((homedir = getenv("HOME"))==NULL)
    {
        homedir = getpwuid(getuid())->pw_dir;
    }
    //char *filepath = (char*)malloc(strlen(homedir)+20);
    //strcpy(filepath,homedir);
    //strcat(filepath,"/.siguseradd");
    //不能用allocate
    char *filepath = (char*)"/home/kwe/.siguseradd";

    char input[100];
    FILE *fp;
    fp=fopen(filepath,"r");
    bool successfile = false;
    if(fp!=NULL)
    {
        while(!feof(fp))
        {
            fscanf(fp, "%s",input);
            if(!strcmp(input, user))//相等
            {
                successfile = true;
                break;
            }
        }

    }
    fclose(fp);
    //free(filepath);
    if(!successfile)
    {
        printf("[WARNING]Can't use sig unlock,Please REGISTER first(siguseradd [username])\n");
        printf("\nYou can still use PASSWORD to unlock.Input next.\n\n");

        return PAM_IGNORE;
    }
    //get username
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

    int pam_set_ret;
    pam_set_ret = pam_set_item(pamh,PAM_AUTHTOK_TYPE,"Now YOU can choose to input password:");
    char ip[16] = "192.168.161.144";
    char port[5] = "1234";
    //产生IP地址和端口号:
    zmq::context_t context (1);
    zmq::socket_t socket (context, ZMQ_REP);
    socket.bind ("tcp://*:1234");

    bool if_exit_login = false;

    printf("->Please open device,input IP and PORT:\n");
    printf("---IP   :%s\n---PORT :%s\n",ip,port);

    while(!if_exit_login&&try_times<N)
    {

        try_times++; //超过N就不能再继续了

        //产生口令
        srand((int)time(NULL));     //每次执行种子不同，生成不同的随机数
        for(int i=0; i<6; i++)
        {
            token[i] = '0'+rand()%10;
        }
        token[6] = '\0';
        printf("->Please open device,input TOKEN:\n");
        printf("---TOKEN:%s\n",token);
        cout<<"->Wait connect...\n";
        //Signatures sigs;

        //等待回答
        end_t_connet_tread = false;
        if (pthread_create(&t_timer[try_times-1], NULL, f_timer, (void *)NULL)) {
            printf("[ERROR]ceateing thread timer");
        }
        if (pthread_create(&t_connet[try_times-1], NULL, f_connect, &socket)) {
            printf("[ERROR]ceateing thread timer");
        }
        pthread_join(t_timer[try_times-1], NULL);

        if(!end_t_connet_tread)//connect没有关闭，在一直响应
        {
            pthread_cancel(t_connet[try_times-1]);
        }


        //得到正确回答
        //返回确认得到回答信号
        if(!getrighttoken&&try_times<N)
        {
            char ch;
            printf("->Wrong Token\n");
            printf("\n->%d/5 Do you want to try again?(Y/n):",try_times);
            scanf("%c",&ch);
            getchar();//去掉换行符
            if(ch != 'Y' && ch != 'y')
            {
                if_exit_login = true;
                continue;
            }
            else
            {
                continue;
            }
        }
        //ifexitlogin = true;//测试版本
        //等待sigs回答
        cout<<"\n->Wait Signatures...\n";
        getrightsigs = false;
        end_t_connet_tread = false;
        if (pthread_create(&t_timer2, NULL, f_timer2, (void *)NULL)) {
            printf("[ERROR]ceateing thread timer");
        }
        if (pthread_create(&t_connet2, NULL, f_connect2, &socket)) {
            printf("[ERROR]ceateing thread timer");
        }
        pthread_join(t_timer2, NULL);
        if(!end_t_connet_tread)//connect没有关闭，在一直响应
        {
            pthread_cancel(t_connet2);
        }
        if(!getrightsigs&&try_times<N)
        {
            char ch;
            printf("->Wrong Token\n");
            printf("\n->%d/5 Do you want to try again?(Y/n):",try_times);
            scanf("%c",&ch);
            getchar();//去掉换行符
            if(ch != 'Y' && ch != 'y')
            {
                if_exit_login = true;
                continue;
            }
            else
            {
                continue;
            }
        }
        //get sigs now just unlock it
        std::cout << "->Check The Signatures Now Please Wait..."<< std::endl;
        opensv::Request t_request;
        t_request.id = username;
        free(username);
        vector <opensv::Signature> t_signatures;
        for (int i=0; i<sigs.signatures_size(); i++) {
            opensv::Signature t_signature;
            vector <opensv::Point> t_points;
            Signature sig1 = sigs.signatures(i);
            for(int j=0;j<sig1.points_size();j++)
            {
                opensv::Point t_point;
                Point p1 = sig1.points(j);
                t_point.t = p1.t();
                t_point.x = p1.x();
                t_point.y = p1.y();
                t_point.p = p1.p();
                t_points.push_back(t_point);
                //cout<<p1.t()<<"b";
              //  cout<<t_point.t<<" "<<t_point.x<<" "<<t_point.y<<" "<<t_point.p<<" "<<endl;

            }
            t_signature.points = t_points;
            t_signatures.push_back(t_signature);
        }

        t_request.signatures = t_signatures;
       // cout<<t_request.signatures.size()<<"b"<<sigs.signatures().size()<<endl;

        //send data to server now
        boost::shared_ptr<TTransport> socket(new TSocket("192.168.161.142", 9090));
        boost::shared_ptr<TTransport> transport(new TBufferedTransport(socket));
        boost::shared_ptr<TProtocol> protocol(new TBinaryProtocol(transport));
        opensv::HandWriterClient client(protocol);
        opensv::Ret ret;
        try {
            transport->open();
            client.verify(ret, t_request);
        } catch (TException &tx) {
            cout << "Error: " << tx.what() << endl;
        }

        bool register_ret = ret.success;
        /*

        zmq::context_t context_c (1);
        zmq::socket_t socket_c (context, ZMQ_REQ);
        socket_c.connect ("tcp://192.168.1.100:1234");
        zmq::message_t request_c (5);
        memcpy (request_c.data (), "hello",5);
        //std::cout << "Sending Hello "  << "..." << std::endl;
        socket_c.send(request_c);
        //  Get the reply.
        zmq::message_t reply_c;
        socket_c.recv (&reply_c);
        char * ret = (char*)malloc(reply_c.size());
        memcpy(ret, reply_c.data(), reply_c.size());
         */
        //必须要返回 才能结束 才能接收下一个recerive
        //关闭也不行
        if(register_ret)
        {
            //解锁成功
            printf("\n ***********************************************\n");
            printf(" *        LOGIN SUCCESS！ CONGRATULATIONS       *\n");//COOL UNLOCK MODULE
            printf(" *       THIS IS A COOL UNLOCK MODULE RIGHT?    *\n");//
            printf(" ***********************************************\n\n");


            return PAM_SUCCESS;
        } else if(try_times<N){
            char ch;
            printf("->Wrong Signature!\n");
            printf("\n->%d/5 Do you want to try again?(Y/n):",try_times);
            scanf("%c",&ch);
            getchar();//去掉换行符
            if(ch != 'Y' && ch != 'y')
            {
                if_exit_login = true;
                continue;
            }
            else
            {
                continue;
            }

        }

    }
    return(PAM_IGNORE);

}

/*
   PAM entry point for setting user credentials (that is, to actually
   establish the authenticated user's credentials to the service provider)
 */
int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return(PAM_SUCCESS);
}

/* PAM entry point for authentication token (password) changes */
int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return(PAM_SUCCESS);
}
