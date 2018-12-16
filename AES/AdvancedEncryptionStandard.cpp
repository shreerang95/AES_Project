#include<iostream>
#include<bits/stdc++.h>
#include"SBOX.h"

using namespace std;

#define Nk 4
#define Nr 10
#define Nb 4


//Class for performing the operations of AES
class AES{

    uint32_t Rcon[Nr];
    uint8_t* aes_key;
    char* key_read;
    uint32_t aes_key_schedule[(Nk*(Nr+1))];
    uint8_t state[Nb][Nb];
    uint8_t input_block[Nb*Nb];
    uint8_t output_block[Nb*Nb];
    fstream key_file;


    public:

    AES(){

        for(int i=0;i<Nr;i++)
            Rcon[i]=0;

        //insert method call to read key
        read_key();

        for(int i=0;i<(Nk*(Nr+1));i++){
            aes_key_schedule[i]={0};
        }
        for(int i=0;i<Nb;i++)
            for(int j=0;j<Nb;j++){
                state[i][j]=0;
            }

        for(int i=0;i<(Nb*Nb);i++){
            output_block[i]=0;
        }

        key_expansion();
    }

    void read_key(){
        if(aes_key != NULL){
            delete aes_key;
        }
        aes_key = new uint8_t[16];
        key_read = new char[17];
        key_file.open("../Key_IV/key.bin",ios::in|ios::binary);
        if(key_file.is_open()){
            key_file.getline(key_read,17);
        }
        for(int i=0;i<16;i++){
            aes_key[i]=key_read[i];
        }
        key_file.close();
        delete key_read;
//        cout<<"KEY: ";
//        for(int i=0;i<16;i++){
//            cout<<hex<<std::setw(2)<<std::setfill('0')<<(aes_key[i]^0x00)<<" ";
//        }
//        cout<<endl;
    }


// method for multiplying a value by 2 and returning the product
    uint8_t xtime(uint8_t x){
        uint16_t product;
        uint8_t res;
        product = x * 2;
        if(product > 0xff){
            product = product ^ 0x11b;
        }

        res = product;

        return res;
    }

// method for multiplying two numbers
    uint8_t mult_GF28(uint8_t x, uint8_t y){
        uint16_t res=0x0000;
        uint16_t temp;
        temp = x;
        while(y>0){
            if(y%2!=0){
                res = res ^ temp;
            }

            temp = xtime(temp);
            y=y/2;

        }
        return res;
    }

// method for generating the round constant array used in key expansion
    void generate_Rcon(){
        uint16_t temp;
        uint8_t Rcon1[Nr];
        Rcon1[0]=0x01;
        Rcon[0] = Rcon1[0];
        Rcon[0]=Rcon[0]<<24;

        for(int i=1;i<Nr;i++){
            temp=(Rcon1[i-1]*2) % 283;
            if(temp>0xff){
                temp = 0x11b - temp;
            }
            Rcon1[i]=temp;
            Rcon[i] = Rcon1[i];
            Rcon[i]=Rcon[i]<<24;
        }
    }

// method to convert the input block to state
    void input_to_state(){

        for(int i=0;i<4;i++)
            for(int j=0;j<4;j++){
                state[j][i]=input_block[(4*i) + j];
            }
    }


    void subbytes(){

        uint8_t new_state[4][4]={{0}};
        uint8_t row_index;
        uint8_t col_index;
        uint8_t temp;

        for(int i=0;i<Nb;i++){
            for(int j=0;j<Nb;j++){
                temp=state[i][j];
                row_index = temp>>4;
                col_index = temp &0x0f;
                new_state[i][j] = SBOX[row_index][col_index];     //remove comment
            }
        }
        for(int i=0;i<Nb;i++){
            for(int j=0;j<Nb;j++){
                state[i][j]=new_state[i][j];
            }
        }
    }


    void shiftrows(){
        uint8_t new_state[4][4];
        for(int i=0;i<Nb;i++){
            for(int j=0;j<Nb;j++){
                new_state[i][j]=state[i][(j+i)%4];
            }
        }

        for(int i=0;i<Nb;i++){
            for(int j=0;j<Nb;j++){
                state[i][j]=new_state[i][j];
            }
        }
    }


    void mixcolumns(){
        uint8_t temp = 0x00;
        uint16_t temp_mul=0x0000;
        uint8_t new_state[4][4] = {{0}};
        for(int i=0;i<Nb;i++){
            for(int j=0;j<Nb;j++){
                temp=0x00;
                for(int k=0;k<Nb;k++){
                    temp_mul = mult_GF28(state[k][j],mbox[i][k]);
                    temp = temp ^ temp_mul;
                }
                new_state[i][j]=temp;
            }
        }

        for(int i=0;i<4;i++){
            for(int j=0;j<4;j++){
                state[i][j]=new_state[i][j];
            }
        }
    }


    void addroundkey(uint8_t start_index){
        uint8_t temp[4];
        uint8_t new_state[4][4];

        for(int i=0;i<Nb;i++){
            for(int j=0;j<Nb;j++){
                temp[j]=(aes_key_schedule[start_index+i] >> (8*(3-j))) & 0x000000ff;
                new_state[j][i]=(state[j][i] ^ temp[j]);
            }
        }

        for(int i=0;i<4;i++){
            for(int j=0;j<4;j++){
                state[i][j]=new_state[i][j];
            }
        }

//        for(int i=0;i<4;i++){
//            for(int j=0;j<4;j++){
//                cout<<hex<<std::setw(2)<<std::setfill('0')<<(new_state[i][j]^0x00)<<" ";
//            }
//            cout<<endl;
//        }
//        cout<<endl;

    }



    uint32_t subword(uint32_t word){

        uint8_t row_index;
        uint8_t col_index;
        uint8_t temp;
        uint32_t result=0x00000000;

        for(int i=0;i<4;i++){
            temp = word >> (8*(3-i));

            row_index = temp>>4;
            col_index = temp & 0x0f;

            if(i!=3){
            result = (result ^ SBOX[row_index][col_index])<<8;
            }
            else if(i==3){
                result = result ^ SBOX[row_index][col_index];
            }
        }
        return result;
    }

    uint32_t rotword(uint32_t word){
        uint32_t temp;
        uint32_t temp1;
        uint32_t result;

        temp = ((word & 0xff000000) >> 24);

        temp1 = word << 8;
        result = temp ^ temp1;

        return result;
    }


    void key_expansion(){
        uint32_t temp;
        int in=0;

        generate_Rcon();

        while(in<Nk){
            for(int j=0;j<Nb;j++){
                aes_key_schedule[in]=aes_key_schedule[in]^aes_key[(4*in) + j];
                if(j!=3){
                    aes_key_schedule[in]=aes_key_schedule[in]<<8;
                }
            }
            in=in+1;
        }

        in=Nk;
        while(in<(Nb*(Nr+1))){
            temp = aes_key_schedule[in-1];

            if(in%Nk == 0){
                temp=(subword(rotword(temp)) ^ Rcon[(in/Nk)-1]);
            }
            else if(Nk>6 && (in%Nk==4)){
                temp = subword(temp);
            }

            aes_key_schedule[in]=aes_key_schedule[in-Nk] ^ temp;
            in=in+1;
        }
    }

// method to encrypt the input block using AES algorithm
    uint8_t*  Encrypt(uint8_t *input){

//        read_key();
        memset(input_block,0,sizeof(input_block));
        for(int i=0;i<(Nb*Nb);i++){
            input_block[i]=input[i];
        }

        input_to_state();
        addroundkey(0);
        for(int i=1;i<Nr;i++){
            subbytes();
            shiftrows();
            mixcolumns();
            addroundkey(i*Nb);
        }
        subbytes();
        shiftrows();
        addroundkey(Nr*Nb);

        for(int i=0;i<Nb;i++)
            for(int j=0;j<Nb;j++){
                output_block[(i*Nb)+j] = state[j][i];
            }

//        for(int i=0;i<(Nb*Nb);i++){
//            cout<<(output_block[i])<<std::flush;
//        }

        return output_block;
    }


    void invsubbytes(){

        uint8_t new_state[4][4]={{0}};
        uint8_t row_index;
        uint8_t col_index;
        uint8_t temp;

        for(int i=0;i<4;i++){
            for(int j=0;j<4;j++){
                temp=state[i][j];
                row_index = temp>>4;
                col_index = temp &0x0f;
                new_state[i][j] = invSBOX[row_index][col_index];
            }
        }

        for(int i=0;i<4;i++){
            for(int j=0;j<4;j++){
                state[i][j] = new_state[i][j];
            }
        }
    }


    void invshiftrows(){
        uint8_t new_state[4][4];
        for(int i=0;i<Nb;i++){
            for(int j=0;j<Nb;j++){
                new_state[i][(j+i)%4]=state[i][j];
            }
        }

        for(int i=0;i<Nb;i++){
            for(int j=0;j<Nb;j++){
                state[i][j]=new_state[i][j];
            }
        }
    }


    void invmixcolumns(){
        uint8_t temp = 0x00;
        uint16_t temp_mul=0x0000;
        uint8_t new_state[4][4] = {{0}};
        for(int i=0;i<4;i++){
            for(int j=0;j<4;j++){
                temp=0x00;
                for(int k=0;k<4;k++){
                    temp_mul = mult_GF28(state[k][j],invmbox[i][k]);
                    temp = temp ^ temp_mul;
                }
                new_state[i][j]=temp;
            }
        }

        for(int i=0;i<4;i++){
            for(int j=0;j<4;j++){
                state[i][j]=new_state[i][j];
            }
        }
    }

// method to decrypt the ciphertext using the AES algorithm
    uint8_t* Decrypt(uint8_t input[Nb*Nb]){

//        read_key();
        for(int i=0;i<(Nb*Nb);i++){
            input_block[i]=input[i];
        }

        input_to_state();
        addroundkey(Nr*Nb);

        for(int i=Nr-1;i>0;i--){
            invshiftrows();
            invsubbytes();
            addroundkey(i*Nb);
            invmixcolumns();
        }

        invshiftrows();
        invsubbytes();
        addroundkey(0);

        for(int i=0;i<Nb;i++)
            for(int j=0;j<Nb;j++){
                output_block[(i*Nb)+j] = state[j][i];
            }


        return output_block;
    }

    ~AES(){
        delete aes_key;
    }
};

//int main(){
////    AES aes;
////    aes.read_key();
////    uint8_t input[16]={0x32,0x43,0xf6,0xa8,0x88,0x5a,0x30,0x8d,0x31,0x31,0x98,0xa2,0xe0,0x37,0x07,0x34};
////    uint8_t input[16]={0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};
////    uint8_t cipher[16]={0x39,0x25,0x84,0x1d,0x02,0xdc,0x09,0xfb,0xdc,0x11,0x85,0x97,0x19,0x6a,0x0b,0x32};
//    uint8_t *cipher;
//    uint8_t input[16]={' ','a',' ','b',' ','c',' ','d',' ','e',' ','f',' ','g',' ','h'};
////    uint8_t key1[16]={0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};
//    uint8_t* output;
//    char ch;
//    string ciphertext="";
//    string plaintext="";
//////  ENCRYPTION
//    AES aes;
////    AES aes(key1);
//    output=aes.Encrypt(input);
//    for(int i=0;i<(Nb*Nb);i++){
//        cout<<(output[i]);
//        ch=(char)output[i];
//        ciphertext=ciphertext+(ch);
//    }
//    cout<<endl;
//    cout<<ciphertext;
//    cout<<endl;
////
//////  Decryption
//    cipher = output;
////    for(int i=0;i<(Nb*Nb);i++){
////        cipher[i]=(uint8_t)ciphertext[i];
////    }
////    for(int i=0;i<(Nb*Nb);i++){
////        cout<<hex<<std::setw(2)<<std::setfill('0')<<(cipher[i]^0x00);
////    }
////    AES aes1(cipher);
//
//    output=aes.Decrypt(cipher);
//
//    for(int i=0;i<(Nb*Nb);i++){
////        cout<<(char)output[i]<<endl;
//        ch=(char)output[i];
//        plaintext=plaintext+(ch);
////        cout<<plaintext<<endl;
//    }
//    cout<<plaintext<<endl;
//}
