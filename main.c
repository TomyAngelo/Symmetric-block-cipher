#include <stdio.h>
#include <openssl/aes.h>
#include <stdlib.h>
#include <string.h>

#define BLOCK_SIZE 16
#define CBC_SIZE 64

void increaseVector(unsigned char * initialVector, int sector){
    for(int i = BLOCK_SIZE-1; i != 0 ; --i){
          initialVector[i]=sector & 0xFF;
          sector=sector>>8;
    }
}

int main(void)
{    
    FILE * ciphertext_ecb;
    FILE * plaintext_ecb;
    FILE * file_key;
    ciphertext_ecb= fopen("aes-ecb.img","rb");
    plaintext_ecb=fopen("ecb_plaintext.img","wb");

    file_key=fopen("key","rb");
    unsigned char key[2*BLOCK_SIZE];
    fread(key,2*BLOCK_SIZE,1,file_key);


    unsigned char *block_16 = (unsigned char*) malloc(BLOCK_SIZE);
    unsigned char *out_block_16 = (unsigned char*) malloc(BLOCK_SIZE);


    AES_KEY key_D;
    AES_set_decrypt_key(key,256,&key_D);

    while (fread(block_16,BLOCK_SIZE,1,ciphertext_ecb) == 1){
        AES_ecb_encrypt(block_16,out_block_16,&key_D,AES_DECRYPT);
        fwrite(out_block_16,BLOCK_SIZE,1,plaintext_ecb);
    }


    //####################
    //###### CBC #########
    //####################

    FILE * ciphertext_cbc_plain64;
    FILE * plaintext_cbc_plain64;
    ciphertext_cbc_plain64=fopen("aes-cbc-plain64.img","rb");
    plaintext_cbc_plain64=fopen("plaintext_aes-cbc-plain64.img","wb");

    //FILE * ciphertext_cbc_essiv_sha256;
    //FILE * plaintext_cbc_essiv_sha256;
    //ciphertext_cbc_essiv_sha256=fopen("aes-cbc-essiv_sha256.img","rb");
    //plaintext_cbc_essiv_sha256=fopen("plaintext_aes-cbc-essiv_sha256.img","wb");

    unsigned char *block_64 = (unsigned char*) malloc(CBC_SIZE);
    unsigned char *out_block_64 = (unsigned char*) malloc(CBC_SIZE);

    unsigned char initialVector[BLOCK_SIZE]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    int sector=0;

    while (fread(block_64,CBC_SIZE,1,ciphertext_cbc_plain64) == 1){
        AES_cbc_encrypt(block_64,out_block_64,CBC_SIZE,&key_D,initialVector,AES_DECRYPT);
        memset(initialVector,0,BLOCK_SIZE);
        fwrite(out_block_64,CBC_SIZE,1,plaintext_cbc_plain64);
        ++sector;
        increaseVector(initialVector,sector);
    }

    fclose(plaintext_cbc_plain64);
    fclose(plaintext_ecb);


    return 0;
}

