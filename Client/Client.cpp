#include<iostream>
#include<bits/stdc++.h>
#include<winsock2.h>
#include<fstream>
#include"../AES/CBC.cpp"


using namespace std;

class Client_Socket{
    WSADATA wsadata;
    SOCKET server;
    SOCKADDR_IN addr;
    blockgenerator* block;
    string ciphertext;
    char* cipher;

    public:

    Client_Socket(){

        WSAStartup(MAKEWORD(2,0), &wsadata);
        server = socket(AF_INET, SOCK_STREAM, 0);

        addr.sin_addr.s_addr = inet_addr("127.0.0.1");
        addr.sin_family = AF_INET;
        addr.sin_port = htons(5555);

        block = new blockgenerator;
    }

    ~Client_Socket(){
        delete block;
    }


    void establish_connection(){
        connect(server,(SOCKADDR*)&addr, sizeof(addr));
        cout<<"Connected to server"<<endl;
    }

    void send_message(char* crypttext, uint64_t csize){
        block->convert_message(crypttext,csize);
        ciphertext = block->goto_encrypt();
        cipher = new char[ciphertext.size()];

        for(int i=0;i<ciphertext.size();i++){
            cipher[i]=char(ciphertext[i]);
        }

        send(server, cipher, ciphertext.size(), 0);

        cout<<"Message sent: ";
        for(int i=0;i<ciphertext.size();i++){
            cout<<cipher[i];
        }
        cout<<endl;

//        for(int i=0;i<ciphertext.size();i++){
//            cout<<hex<<std::setw(2)<<std::setfill('0')<<((uint8_t)cipher[i]^0x00)<<" ";
//        }
//        cout<<endl;
        delete cipher;
    }
    void close_sock(){
        closesocket(server);
        WSACleanup();
        cout<<"Socket Closed"<<endl;
    }
};

int main(){

    Client_Socket csocket;
    char send_message[1024];
    string message;
    string ans="Y";

    csocket.establish_connection();

    while(ans[0]=='Y' || ans[0]=='y'){
        cout<<"Enter message to be sent: ";
        getline(cin,message);
        std::cin.clear();

        for(int i=0;i<message.length();i++){
            send_message[i]=(char)message[i];
        }

        csocket.send_message(send_message,message.size());
        cout<<"Want to send more messages?(y/n) ";
        getline(cin,ans);
        std::cin.clear();
        memset(send_message,0,sizeof(send_message));
    }
    csocket.close_sock();
}
