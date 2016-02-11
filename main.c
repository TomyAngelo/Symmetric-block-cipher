#include <stdio.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/modes.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

//#include <aes_xts/xts.h>
//#include <aes_xts/aes.h>
//#include <aes_xts/brg_types.h>
//#include <aes_xts/mode_hdr.h>



#define BLOCK_SIZE 16
#define SECTOR_SIZE 512

//void increaseVector(unsigned char * initialVector, int sector){
//    for(int i = BLOCK_SIZE-1; i != 0 ; --i){
//          initialVector[i]=sector & 0xFF;
//          sector=sector>>8;
//    }
//}

void increaseVector2(unsigned char * initialVector, int sector){
    for(int i = 0; i != BLOCK_SIZE-1 ; ++i){
          initialVector[i]=sector & 0xFF;
          sector=sector<<8;
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
    //uint64_t initialVector=0;

    int sector=0;

    while (fread(block_512,SECTOR_SIZE,1,ciphertext_cbc_plain64) == 1){
        AES_cbc_encrypt(block_512,out_block_512,SECTOR_SIZE,&key_D,initialVector,AES_DECRYPT);
        fwrite(out_block_512,SECTOR_SIZE,1,plaintext_cbc_plain64);
        memset(initialVector,0,BLOCK_SIZE);
        ++sector;
        increaseVector2(initialVector,sector);
    }

    fclose(plaintext_cbc_plain64);
//---------------------------------------------------------------------------------
    // ################### SHA256 ##################

    FILE * ciphertext_cbc_essiv_sha256;
    FILE * plaintext_cbc_essiv_sha256;
    ciphertext_cbc_essiv_sha256=fopen("aes-cbc-essiv_sha256.img","rb");
    plaintext_cbc_essiv_sha256=fopen("plaintext_aes-cbc-essiv_sha256.img","wb");

    memset(initialVector,0,BLOCK_SIZE);
    sector=0;

    AES_KEY key_Dh;
    unsigned char hash_key[2*BLOCK_SIZE];
    SHA256_CTX sha_key;
    SHA256_Init(&sha_key);
    SHA256_Update(&sha_key, key, 2*BLOCK_SIZE);
    SHA256_Final(hash_key, &sha_key);

    AES_set_decrypt_key(hash_key,256,&key_Dh);

    //unsigned char nullVector[BLOCK_SIZE];

    while (fread(block_512,SECTOR_SIZE,1,ciphertext_cbc_essiv_sha256) == 1){
        //memset(nullVector,0,BLOCK_SIZE);

        AES_cbc_encrypt(initialVector,initialVector,BLOCK_SIZE,&key_Dh,initialVector,AES_DECRYPT);

        AES_cbc_encrypt(block_512,out_block_512,SECTOR_SIZE,&key_D,initialVector,AES_DECRYPT);
        fwrite(out_block_512,SECTOR_SIZE,1,plaintext_cbc_essiv_sha256);
        memset(initialVector,0,BLOCK_SIZE);
        ++sector;
        increaseVector2(initialVector,sector);

    }


    fclose(plaintext_cbc_essiv_sha256);

    //########################
    //######### XTS ##########
    //########################





//int main(void)
//{
//    FILE * ciphertext_xts;
//    FILE * plaintext_xts;
//    ciphertext_xts=fopen("aes-xts-plain64.img","rb");
//    plaintext_xts=fopen("plaintext-aes-xts.img","wb");

//    FILE * file_key;
//    file_key=fopen("key","rb");
//    unsigned char key[2*BLOCK_SIZE];
//    fread(key,2*BLOCK_SIZE,1,file_key);

//    unsigned char *block_xts = (unsigned char*) malloc(BLOCK_SIZE);

//    lba_type vector=0;
//    xts_decrypt_ctx xtsContext;
//    xts_decrypt_key( key, 2*BLOCK_SIZE, &xtsContext );

//    while (fread(block_xts,SECTOR_SIZE,1,ciphertext_xts) == 1){
//        xts_decrypt_sector( block_xts, vector,SECTOR_SIZE, &xtsContext );
//        fwrite(block_xts,SECTOR_SIZE,1,plaintext_xts);
//        ++vector;
//    }

//    fclose(plaintext_xts);

    return 0;
}

