#include<iostream>
#include<bits/stdc++.h>
#include"AdvancedEncryptionStandard.cpp"

using namespace std;

#define Nk 4

// Class to implement Cipher Block Chaining mode of operation
class blockgenerator{
    uint8_t *input;
    char* iv_read;
    uint8_t *init_vector;
    uint64_t isize;
    uint64_t bnum;
    uint8_t pnum;
    uint8_t **block;
    uint8_t *return_block;
    string cipher;
    AES* aes;
    uint8_t *cbc_op_output;
    fstream iv_file;
    uint8_t* message;

    public:

    blockgenerator(){
        // Generate the initialization vector

        isize=-1;
        bnum=-1;
        pnum=-1;
    }

// deallocate the memory allocated to the input blocks
    ~blockgenerator(){
        delete aes;
        delete block;

    }

    void read_iv(){

        aes = new AES;
        if(init_vector != NULL){
            delete init_vector;
        }
        init_vector = new uint8_t[16];
        iv_read = new char[17];

        iv_file.open("../Key_IV/IV.bin",ios::in|ios::binary);
        if(iv_file.is_open()){
            iv_file.getline(iv_read,17);
        }
        for(int i=0;i<16;i++){
            init_vector[i]=iv_read[i];
        }
        iv_file.close();
        delete iv_read;
//        cout<<"IV: ";
//        for(int i=0;i<16;i++){
//            cout<<hex<<std::setw(2)<<std::setfill('0')<<(init_vector[i]^0x00)<<" ";
//        }
//        cout<<endl;
    }

    void convert_message(char* input_message, int msize){
        read_iv();
        message = new uint8_t[msize];
        for(int i=0;i<msize;i++){
            message[i]=(uint8_t)input_message[i];
        }

        generate_blocks(message,msize);
        delete message;
    }

// method to generate input blocks from plaintext
    void generate_blocks(uint8_t *message, uint64_t msize){

        input = message;
        isize = msize;

        if(msize<(Nk * 4)){
            bnum=1;
        }
        else{
            bnum = floor(msize/(Nk*4)) + 1;
        }

        block = new uint8_t*[bnum];
        if(block == NULL){
            cout<<"Bad Allocation";
            exit(EXIT_FAILURE);
        }
        for(int i=0;i<bnum;i++){
            block[i] = new uint8_t[Nk*4];
            if(block[i] == NULL){
                cout<<"Bad Allocation";
                exit(EXIT_FAILURE);
            }

        }

        for(uint64_t i=0,b=0;(i<isize && b<bnum);i=i+(Nk*4),b++){
            for(uint64_t j=0;(j<16 && ((i+j)<isize));j++){
                block[b][j] = input[i+j];
            }
        }

        pnum = (bnum*Nk*4) - isize;

        for(uint8_t i = ((Nk*4)-pnum); i<(Nk*4);i++){
            block[bnum-1][i] = pnum;
        }

//        for(int i=0;i<bnum;i++){
//            for(int j=0;j<Nk*4;j++){
//                cout<<hex<<std::setw(2)<<std::setfill('0')<<(block[i][j]^0x00)<<" ";
//            }
//            cout<<endl;
//        }

    }

// method for performing XOR with one element of the input block
    uint8_t CBC_op1(uint8_t cbc_op_input, uint8_t iv){
        uint8_t cbc_op_output;
        cbc_op_output=cbc_op_input ^ iv;
        return cbc_op_output;
    }

// method which calls the encrypt method of AES class and returns the ciphertext
    string goto_encrypt(){
        string cipher="";
        uint8_t input_block[16]={};
        uint8_t *cbc_op_output_block;
        uint8_t *encrypt_input_block;
        uint8_t* iv;

        char ch;

//        cout<<"IV: ";
//        for(int i=0;i<16;i++){
//            cout<<hex<<std::setw(2)<<std::setfill('0')<<(init_vector[i]^0x00)<<" ";
//        }
//        cout<<endl;


        for(int i=0;i<bnum;i++){

            memset(input_block,0,sizeof(input_block));
            cbc_op_output_block=NULL;
            cbc_op_output_block=new uint8_t[sizeof(input_block)];

            if(cbc_op_output_block == NULL){
                cout<<"Bad Allocation";
                exit(EXIT_FAILURE);
            }


            for(int j=0;j<(Nk*4);j++){
                    input_block[j]=block[i][j];
            }

            if(i==0){
                iv = init_vector;
            }
            else{
                iv = return_block;
            }


            for(int j=0;j<sizeof(input_block);j++){
                cbc_op_output_block[j] = CBC_op1(input_block[j],iv[j]);
            }


            return_block = aes->Encrypt(cbc_op_output_block);

            for(int i=0;i<(Nb*Nb);i++){
                ch=(char)return_block[i];
                cipher=cipher+(ch);
            }
        }
        delete cbc_op_output_block;
        return cipher;
    }

// method which calls the decrypt methodof the AES class and returns the plaintext
    string goto_decrypt(){
        string plaintext="";
        string plaintext1="";
        int index;
        uint8_t *cbc_op_output_block;
        uint8_t* in_vec;
        uint8_t* c_block;


        bnum = bnum-1;
        uint8_t input_block[16]={};
        char ch;

        for(int i=0;i<bnum;i++){
            memset(input_block,0,sizeof(input_block));
            cbc_op_output_block=NULL;
            cbc_op_output_block=new uint8_t[sizeof(input_block)];

            if(cbc_op_output_block == NULL){
                cout<<"Bad Allocation";
                exit(EXIT_FAILURE);
            }


            in_vec=NULL;
            in_vec=new uint8_t[sizeof(input_block)];

            if(in_vec == NULL){
                cout<<"Bad Allocation";
                exit(EXIT_FAILURE);
            }


            for(int j=0;j<(Nk*4);j++){
                    input_block[j]=block[i][j];
            }

            if(i==0){
                in_vec = init_vector;
            }
            else{
                in_vec = block[i-1];
            }


            return_block = aes->Decrypt(input_block);

            for(int j=0;j<sizeof(input_block);j++){

                cbc_op_output_block[j] = CBC_op1(return_block[j], in_vec[j]);
            }

            for(int j=0;j<sizeof(input_block);j++){
                ch=(char)cbc_op_output_block[j];
                plaintext=plaintext+(ch);
            }
        }

        index = int(plaintext[plaintext.size()-1]);

        for(int i=0;i<(plaintext.size()-index);i++){
            plaintext1 = plaintext1+plaintext[i];
        }

        delete cbc_op_output_block;
        delete in_vec;
        return plaintext1;
    }
};


//int main(){
//    blockgenerator block;
//    block.read_iv();
////string input_message=" a b c d e f g h i j k l m n o p q";
//////string input_message=" a b c d e f g h";
////string ciphertext="";
////string plaintext1="";
////uint64_t msize = input_message.size();
////uint8_t *message = new uint8_t[msize];
////
////if(message == NULL){
////    cout<<"Bad Allocation";
////    exit(EXIT_FAILURE);
////}
////
//////uint8_t message[16]={0x32,0x43,0xf6,0xa8,0x88,0x5a,0x30,0x8d,0x31,0x31,0x98,0xa2,0xe0,0x37,0x07,0x34};
////for(int i=0;i<input_message.size();i++){
////    message[i]=(uint8_t)input_message[i];
////}
////
////blockgenerator block;
////block.generate_blocks(message,msize);
////
////ciphertext=block.goto_encrypt();
////
////cout<<"Ciphertext after encryption: ";
////cout<<ciphertext<<std::flush<<endl;
////
////msize = ciphertext.size();
////message = new uint8_t[msize];
////
////if(message == NULL){
////    cout<<"Bad Allocation";
////    exit(EXIT_FAILURE);
////}
////
////for(int i=0;i<ciphertext.size();i++){
////    message[i]=(uint8_t)ciphertext[i];
////}
////
////block.generate_blocks(message,msize);
////plaintext1=block.goto_decrypt();
////
////cout<<"Plaintext after decryption: ";
////cout<<plaintext1<<std::flush<<endl;
////
////delete message;
////return 0;
//}
