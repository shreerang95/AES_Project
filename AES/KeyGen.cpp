#include <Windows.h>
#include <Wincrypt.h>
#include<iostream>
#include<bits/stdc++.h>

using namespace std;

// Class to generate random numbers which can be used as keys and initialization vectors
class KeyGen{
    HCRYPTPROV   hCryptProv;
    HCRYPTKEY    hOriginalKey;
    DWORD        dwMode;
    BYTE         pbData[16];

public:
    KeyGen()
    {

        CryptAcquireContext(&hCryptProv,NULL,NULL,PROV_RSA_AES,0);

        CryptGenKey(hCryptProv,CALG_AES_128,0,&hOriginalKey);

        dwMode = CRYPT_MODE_CBC;
        CryptSetKeyParam(hOriginalKey,KP_MODE,(BYTE*)&dwMode,0);
    }

// method to generate the random value
    void generate_key(){
        CryptGenRandom(hCryptProv,16,pbData);
    }

// method to retrieve the random value
    uint8_t* get_key(){
//        cout<<"KEY!!! ";
//        for(int i=0;i<16;i++){
//            cout<<hex<<std::setw(2)<<std::setfill('0')<<(pbData[i]^0x00);
//        }
//        cout<<endl;
        return pbData;
    }

//method to delete the generated random value
    void destroy_key(){
        if (hOriginalKey){
            CryptDestroyKey(hOriginalKey);
        }
//
        if(hCryptProv){
            CryptReleaseContext(hCryptProv, 0);
        }
    }
};


//int main(){
////    KeyGen keygen;
////
////    keygen.func();
////    keygen();
//
//    uint8_t key[16]={};
//
//    KeyGen kgen;
//    kgen.generate_key();
//    key = kgen.get_key();
//    for(int i=0;i<16;i++){
//        cout<<hex<<std::setw(2)<<std::setfill('0')<<(key[i]^0x00);
//    }
//}
