#include <stdio.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <stdlib.h>
#include <string.h>

#define BLOCK_SIZE 16
#define SECTOR_SIZE 512

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

      fclose(plaintext_ecb);


    //####################
    //###### CBC #########
    //####################

    FILE * ciphertext_cbc_plain64;
    FILE * plaintext_cbc_plain64;
    ciphertext_cbc_plain64=fopen("aes-cbc-plain64.img","rb");
    plaintext_cbc_plain64=fopen("plaintext_aes-cbc-plain64.img","wb");    

    unsigned char *block_512 = (unsigned char*) malloc(SECTOR_SIZE);
    unsigned char *out_block_512 = (unsigned char*) malloc(SECTOR_SIZE);

    unsigned char initialVector[BLOCK_SIZE]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

    int sector=0;

    while (fread(block_512,SECTOR_SIZE,1,ciphertext_cbc_plain64) == 1){
        AES_cbc_encrypt(block_512,out_block_512,SECTOR_SIZE,&key_D,initialVector,AES_DECRYPT);
        fwrite(out_block_512,SECTOR_SIZE,1,plaintext_cbc_plain64);
        memset(initialVector,0,BLOCK_SIZE);
        ++sector;
        increaseVector(initialVector,sector);
    }

    fclose(plaintext_cbc_plain64);



    FILE * ciphertext_cbc_essiv_sha256;
    FILE * plaintext_cbc_essiv_sha256;
    ciphertext_cbc_essiv_sha256=fopen("aes-cbc-essiv_sha256.img","rb");
    plaintext_cbc_essiv_sha256=fopen("plaintext_aes-cbc-essiv_sha256.img","wb");

    memset(initialVector,0,BLOCK_SIZE);


    sector=0;
    while (fread(block_512,SECTOR_SIZE,1,ciphertext_cbc_essiv_sha256) == 1){

        unsigned char hash[BLOCK_SIZE];
        SHA256_CTX sha256;
        SHA256_Init(&sha256);
        SHA256_Update(&sha256, initialVector, BLOCK_SIZE);
        SHA256_Final(hash, &sha256);

        AES_cbc_encrypt(block_512,out_block_512,SECTOR_SIZE,&key_D,hash,AES_DECRYPT);
        fwrite(out_block_512,SECTOR_SIZE,1,plaintext_cbc_essiv_sha256);
        memset(initialVector,0,BLOCK_SIZE);
        ++sector;
        increaseVector(initialVector,sector);
    }
    fclose(plaintext_cbc_essiv_sha256);


    return 0;
}

