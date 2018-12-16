#include<iostream>
#include<bits/stdc++.h>
#include<winsock2.h>
#include"../AES/KeyGen.cpp"
#include"../AES/CBC.cpp"

using namespace std;

class Server_Socket{
    WSADATA wsadata;
    SOCKET client;
    SOCKET server;
    SOCKADDR_IN server_addr;
    SOCKADDR_IN client_addr;
    int clientAddrSize;
    char message[1024];
    uint8_t *cipher;
    int64_t msg_length;
    blockgenerator* block;
    string plaintext;
    KeyGen* kgen;
    uint8_t* key;
    uint8_t* iv;
    char* write_key;
    char* write_iv;
    fstream key_file;
    fstream iv_file;


    public:
    Server_Socket(){
        WSAStartup(MAKEWORD(2,0), &wsadata);
        server = socket(AF_INET, SOCK_STREAM, 0);

        clientAddrSize = sizeof(client_addr);

        server_addr.sin_addr.s_addr = INADDR_ANY;
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(5555);

        bind(server, (SOCKADDR *)&server_addr, sizeof(server_addr));
        listen(server, 0);
        cout<<"Awaiting reception of message..."<<endl;

        store_key();
        store_iv();

        block = new blockgenerator;
    }

    ~Server_Socket(){
        delete block;
    }


    void store_key(){
        kgen = new KeyGen;
        kgen->generate_key();
        key = new uint8_t[17];
        write_key = new char[17];
        key = kgen->get_key();

//        cout<<"KEY ";
//        for(int i=0;i<16;i++){
//            cout<<hex<<std::setw(2)<<std::setfill('0')<<(key[i]^0x00)<<" ";
//        }
//        cout<<endl;

        for(int i=0;i<16;i++){
            write_key[i] = (char)key[i];
        }
        write_key[16]='\0';
        key_file.open("../Key_IV/key.bin",ios::out|ios::binary);
        if(key_file.is_open()){
            key_file.write(write_key,17);
        }
        key_file.close();
        kgen->destroy_key();
        delete key;
        delete write_key;
        delete kgen;
    }

    void store_iv(){
        kgen = new KeyGen;
        kgen->generate_key();
        iv = new uint8_t[17];
        write_iv = new char[17];
        iv = kgen->get_key();

//        cout<<"IV ";
//        for(int i=0;i<16;i++){
//            cout<<hex<<std::setw(2)<<std::setfill('0')<<(iv[i]^0x00)<<" ";
//        }
//        cout<<endl;

        for(int i=0;i<16;i++){
            write_iv[i] = (char)iv[i];
        }
        write_iv[16]='\0';
        iv_file.open("../Key_IV/IV.bin",ios::out|ios::binary);
        if(iv_file.is_open()){
            iv_file.write(write_iv,17);
        }
        iv_file.close();
        kgen->destroy_key();
        delete kgen;
        delete iv;
        delete write_iv;
    }


    bool establish_connection(){
        if((client = accept(server,(SOCKADDR*)&client_addr, &clientAddrSize)) != INVALID_SOCKET){
            cout<<"Connection established! "<<endl<<"Receiving message..."<<endl;
            return true;
        }
        else{
            return false;
        }
    }

    void receive_message(){

        msg_length = recv(client,message, sizeof(message),0);
        cipher = new uint8_t[msg_length];
        cout<<"Received message: ";
        for(int i=0;i<msg_length;i++){
            cout<<message[i];
        }
        cout<<endl;
        block->convert_message(message,msg_length);
        plaintext = block->goto_decrypt();
        cout<<"Decrypted message: "<<plaintext;
        memset(message,0,sizeof(message));
        cout<<endl;
        delete cipher;
    }

    void close_sock(){
        closesocket(client);
        cout<<endl;
        cout<<"Client Disconnected!"<<endl;
    }

};

int main(){

    Server_Socket ssocket;
    string ans="Y";
    if(ssocket.establish_connection()){
        while(ans[0]=='y' || ans[0]=='Y'){
            ssocket.receive_message();
            cout<<"Want to receive messages?(y/n) ";
            getline(cin,ans);
        }
    }
    ssocket.close_sock();
    std::cin.ignore();
}
