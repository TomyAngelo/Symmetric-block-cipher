#include <stdio.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define BLOCK_SIZE 16
#define SECTOR_SIZE 512
#define SECTOR_SHIFT 9
/**
 * @brief counts logaritm
 * @param x is the number from which is logaritm counted
 * @return is logaritm value to number x
 */
static int int_log2(unsigned int x)
{
    int r = 0;
    for (x >>= 1; x > 0; x >>= 1)
        r++;
    return r;
}
/**
 * @brief set number of sector to param initialVector
 * @param initialVector is 32 bit number
 * @param sector is number of the sector
 */
void increaseVector32(unsigned char * initialVector, int sector){
    for(int i = 0; i != BLOCK_SIZE/2-1 ; ++i){
          initialVector[i] = sector & 0xFF;
          sector = sector >> 8;
    }
}
/**
 * @brief set number of sector to param initialVector
 * @param initialVector is 64 bit number
 * @param sector is number of the sector
 */
void increaseVector64(unsigned char * initialVector, int sector){
    for(int i = 0; i != BLOCK_SIZE-1 ; ++i){
          initialVector[i] = sector & 0xFF;
          sector = sector >> 8;
    }
}
/**
 * @brief set benbi vector
 * @param initialVector is 64 bit number
 * @param sector is number of the sector
 */
void setBenbiIV(unsigned char * initialVector, int sector){
    for(int i = BLOCK_SIZE-1; i != 0 ; --i){
          initialVector[i] = sector & 0xFF;
          sector = sector >> 8;
    }
}
/**
 * @brief nacitava kluc zo suboru
 * @param key is param to which is loading key
 * @param keyFile containts path to file with key
 * @param size is size of key which should be load
 */
void loadKey(unsigned char* key, char* keyFile, int size){
    FILE * file_key = fopen(keyFile,"rb");
    if(file_key == NULL){
        fprintf(stderr, "Failed to open file with key\n" );
        exit(1);
    }
    if(fread(key,size,1,file_key) != 1 ){
        fprintf(stderr, "Fail during loading key\n");
        exit(1);
    }
    fclose(file_key);
    return ;
}
/**
 * @brief set initialization vector
 * @param nameOfIV is name of initialization vector
 * @param initialVector is initialization vector
 * @param sector is number of sector on disk
 * @param key_hash is needed when vector ESSIV is setting, he containts hashed key by hash function SHA256
 * @param benbi_shift is value of shift for benbi vector
 */
void setInitialVector(char * nameOfIV, unsigned char * initialVector, int sector, AES_KEY *key_hash, int benbi_shift ){
    if(strcmp(nameOfIV,"plain") == 0){
        memset(initialVector,0,BLOCK_SIZE/2);
    }else{
        memset(initialVector,0,BLOCK_SIZE);
    }

    if(strcmp(nameOfIV,"plain") == 0){
        increaseVector32(initialVector,sector);
    }
    if(strcmp(nameOfIV,"plain64") == 0){
        increaseVector64(initialVector,sector);
    }
    if(strcmp(nameOfIV,"essiv") == 0){
        increaseVector64(initialVector,sector);
        AES_ecb_encrypt(initialVector,initialVector,key_hash,AES_ENCRYPT);
    }
    if(strcmp(nameOfIV,"benbi") == 0){
        setBenbiIV(initialVector,(sector << benbi_shift) + 1);
    }
}
/**
 * @brief key is hashed by hash function SHA256
 * @param keyStr is string contains key
 * @param size is size of key
 * @param key_hash is output param where will be hashed key stored
 * @return 0 if everything is OK 1 otherwise
 */
int SHA256hashing(unsigned char * keyStr, int size, AES_KEY *key_hash){
    unsigned char hash_key[2*BLOCK_SIZE];
    SHA256_CTX sha_key;
    if(SHA256_Init(&sha_key) != 1){
        return 1;
    }
    if(SHA256_Update(&sha_key, keyStr, size) != 1){
        return 1;
    }
    if(SHA256_Final(hash_key, &sha_key) != 1){
        return 1;
    }
    if(AES_set_encrypt_key(hash_key,size*8,key_hash) != 0){
        return 1;
    }
    return 0;
}
/**
 * @brief free alocated memory
 */
void freeAll(EVP_CIPHER_CTX* ctx, unsigned char **block, unsigned char **out_block, unsigned char **initialVector ){
    if(ctx != NULL){
        EVP_CIPHER_CTX_free(ctx);
    }
    free(*initialVector);
    free(*block);
    free(*out_block);
}

/**
 * @brief encrypt or decrypt disk image with cipher AES-CBC
 * @param inputFile is input file which should be encrypt or decrypt
 * @param output is output file after processing file inputFile
 * @param keyStr is string contains key
 * @param keySize is size of key
 * @param enc in flag if input file should be encrypt or decrypt
 * @param iv is name of initialization vector
 * @param sizeFrom is number of sector from which should start encryption or decryption
 * @param sizeTo is number of sector to which should end encryption or decryption
 */
void cbcEncryption(FILE* inputFile,FILE* output, unsigned char* keyStr, int keySize, char enc, char *iv, int sizeFrom, int sizeTo ){
    unsigned char *block = (unsigned char*) malloc(SECTOR_SIZE);
    unsigned char *out_block = (unsigned char*) malloc(SECTOR_SIZE);
    unsigned char *initialVector;

    if(strcmp(iv,"plain") == 0){
        initialVector = (unsigned char*) malloc(BLOCK_SIZE/2);
        memset(initialVector,0,BLOCK_SIZE/2);
    }else{
        initialVector = (unsigned char*) malloc(BLOCK_SIZE);
        memset(initialVector,0,BLOCK_SIZE);
    }

    AES_KEY key;
    AES_KEY key_hash;

    if(enc == 'e'){
        if(AES_set_encrypt_key(keyStr,keySize*8,&key) != 0){
            fprintf(stderr, "Setting encrypt key failed\n" );
            freeAll(NULL,&block,&out_block,&initialVector);
            exit(1);
        }
    }
    if(enc == 'd'){
        if(AES_set_decrypt_key(keyStr,keySize*8,&key) != 0){
            fprintf(stderr, "Setting decrypt key failed\n" );
            freeAll(NULL,&block,&out_block,&initialVector);
            exit(1);
        }
    }

    if(strcmp(iv,"essiv") == 0){
        if(SHA256hashing(keyStr,keySize,&key_hash) !=0 ){
           fprintf(stderr, "Hashing failed\n" );
           freeAll(NULL,&block,&out_block,&initialVector);
           exit(1);
        }
    }

    int benbi_shift;
    if(strcmp(iv,"benbi") == 0){
        int log = int_log2(BLOCK_SIZE);
        if(log > SECTOR_SHIFT){
            fprintf(stderr, "Log is bigger than shift\n" );
            freeAll(NULL,&block,&out_block,&initialVector);
            exit(1);
        }
      benbi_shift = SECTOR_SHIFT - log;
    }

    int sector = 0;
    while(sector < sizeFrom){
        fread(block,SECTOR_SIZE,1,inputFile);       
        ++sector;
    }

    setInitialVector(iv,initialVector,sector,&key_hash,benbi_shift);

    while (fread(block,SECTOR_SIZE,1,inputFile) == 1){
        setInitialVector(iv,initialVector,sector,&key_hash,benbi_shift);

        if(enc == 'e'){
            AES_cbc_encrypt(block,out_block,SECTOR_SIZE,&key,initialVector,AES_ENCRYPT);
        }else if(enc == 'd'){
            AES_cbc_encrypt(block,out_block,SECTOR_SIZE,&key,initialVector,AES_DECRYPT);
        }

        if(fwrite(out_block,SECTOR_SIZE,1,output) != 1) {
            fprintf(stderr, "Writing to file failed\n" );
            freeAll(NULL,&block,&out_block,&initialVector);
            exit(1);
        }
        ++sector;
        if(sector == INT_MAX || (sector > sizeTo && sizeTo != 0)) break;

    }
     freeAll(NULL,&block,&out_block,&initialVector);
}

/**
 * @brief encrypt or decrypt disk image with cipher AES-XTS
 * @param inputFile is input file which should be encrypt or decrypt
 * @param output is output file after processing file inputFile
 * @param keyStr is string contains key
 * @param keySize is size of key
 * @param enc in flag if input file should be encrypt or decrypt
 * @param iv is name of initialization vector
 * @param sizeFrom is number of sector from which should start encryption or decryption
 * @param sizeTo is number of sector to which should end encryption or decryption
 */
void xtsEncryption(FILE* inputFile,FILE* output, unsigned char* keyStr,int keySize, char enc, char *iv, int sizeFrom, int sizeTo){
    unsigned char *block = (unsigned char*) malloc(SECTOR_SIZE);
    unsigned char *out_block = (unsigned char*) malloc(SECTOR_SIZE);
    unsigned char *initialVector;

    if(strcmp(iv,"plain") == 0){
        initialVector = (unsigned char*) malloc(BLOCK_SIZE/2);
        memset(initialVector,0,BLOCK_SIZE/2);
    }else{
        initialVector = (unsigned char*) malloc(BLOCK_SIZE);
        memset(initialVector,0,BLOCK_SIZE);
    }

    AES_KEY key_hash;
    if(strcmp(iv,"essiv") == 0){
        if(SHA256hashing(keyStr,keySize,&key_hash) !=0 ){
           fprintf(stderr, "Hashing failed\n" );
           freeAll(NULL,&block,&out_block,&initialVector);
           exit(1);
        }
    }

    int benbi_shift;
    if(strcmp(iv,"benbi") == 0){
        int log = int_log2(BLOCK_SIZE);
        if(log > SECTOR_SHIFT){
            fprintf(stderr, "Log is bigger than shift\n" );
            freeAll(NULL,&block,&out_block,&initialVector);
            exit(1);
        }
      benbi_shift = SECTOR_SHIFT - log;
    }

    EVP_CIPHER_CTX *ctx;
    int len;

    int sector = 0;
    while(sector < sizeFrom){
        fread(block,SECTOR_SIZE,1,inputFile);
        ++sector;
    }

    setInitialVector(iv,initialVector,sector,&key_hash,benbi_shift);

    while (fread(block,SECTOR_SIZE,1,inputFile) == 1){
        if(! (ctx = EVP_CIPHER_CTX_new())){
           fprintf(stderr, "Initialization context failed\n" );
           freeAll(ctx,&block,&out_block,&initialVector);
           exit(1);
        }
        setInitialVector(iv,initialVector,sector,&key_hash,benbi_shift);
        if(enc == 'e'){
            if(keySize == 32){
                if(EVP_EncryptInit(ctx, EVP_aes_128_xts(), keyStr, initialVector) != 1){
                    fprintf(stderr, "Encryption failed(EVP_EncryptInit)\n" );
                    freeAll(ctx,&block,&out_block,&initialVector);
                    exit(1);
                }
            }else{
                if(EVP_EncryptInit(ctx, EVP_aes_256_xts(), keyStr, initialVector) != 1){
                    fprintf(stderr, "Encryption failed(EVP_EncryptInit)\n" );
                    freeAll(ctx,&block,&out_block,&initialVector);
                    exit(1);
                }
            }
            if(EVP_EncryptUpdate(ctx, out_block, &len, block, SECTOR_SIZE) != 1){
                fprintf(stderr, "Encryption failed(EVP_EncryptUpdate)\n" );
                freeAll(ctx,&block,&out_block,&initialVector);
                exit(1);
            }
            if(EVP_EncryptFinal(ctx, out_block + len, &len) != 1){
                fprintf(stderr, "Encryption failed(EVP_EncryptFinal)\n" );
                freeAll(ctx,&block,&out_block,&initialVector);
                exit(1);
            }
        }else if(enc == 'd'){
            if(keySize == 32){
                if(EVP_DecryptInit(ctx, EVP_aes_128_xts(), keyStr, initialVector) != 1){
                    fprintf(stderr, "Decryption failed(EVP_DecryptInit)\n" );
                    freeAll(ctx,&block,&out_block,&initialVector);
                    exit(1);
                }
            }else{
                if(EVP_DecryptInit(ctx, EVP_aes_256_xts(), keyStr, initialVector) != 1){
                    fprintf(stderr, "Decryption failed(EVP_DecryptInit)\n" );
                    freeAll(ctx,&block,&out_block,&initialVector);
                    exit(1);
                }
            }
            if(EVP_DecryptUpdate(ctx, out_block, &len, block, SECTOR_SIZE) != 1){
                fprintf(stderr, "Decryption failed(EVP_DecryptUpdate)\n" );
                freeAll(ctx,&block,&out_block,&initialVector);
                exit(1);
            }
            if(EVP_DecryptFinal(ctx, out_block + len, &len) != 1){
                fprintf(stderr, "Decryption failed(EVP_DecryptFinal)\n" );
                freeAll(ctx,&block,&out_block,&initialVector);
                exit(1);
            }
        }
        if(fwrite(out_block,SECTOR_SIZE,1,output) != 1) {
            fprintf(stderr, "Writing to file failed\n" );
            freeAll(ctx,&block,&out_block,&initialVector);
            exit(1);
        }

        ++sector;
        if(sector == INT_MAX || (sector > sizeTo && sizeTo != 0)) break;
    }
    freeAll(ctx,&block,&out_block,&initialVector);
}

int main(int argc, char *argv[]){

    if(argc != 7 && argc != 9){
        fprintf(stderr, "Incorrect number of parameters\n" );
        exit(1);
    }

    FILE * inputFile;
    inputFile = fopen(argv[1],"rb");
    if(inputFile == NULL){
        fprintf(stderr, "Failed to open file\n" );
        exit(1);
    }
    FILE * file_key = fopen(argv[2],"rb");
    int fileSize;
    fseek (file_key , 0 , SEEK_END);
    fileSize = ftell (file_key);
    rewind (file_key);
    if(fileSize != 16 && fileSize != 32 && fileSize != 64){
        fprintf(stderr, " Size of key is incorrect. Size of key must be 16, 32 or 64 bytes\n" );
        return 1;
    }
    fclose(file_key);

    unsigned char key[fileSize];
    loadKey(key,argv[2],fileSize);

    if(strlen(argv[3]) != 1 || !(argv[3][0] == 'e' || argv[3][0] == 'd') ){
        fprintf(stderr, "A bad character or more characters were entered in the third parameter\n" );
        exit(1);
    }
    char encryption=argv[3][0];

    if(strlen(argv[4]) != 3 || !(strcmp(argv[4] , "cbc") == 0 || strcmp(argv[4] , "xts") == 0)){
        fprintf(stderr, "Bad mode\n" );
        exit(1);
    }

    char mode[strlen(argv[4])];
    strcpy(mode,argv[4]);

    if( ( strcmp(argv[4] , "cbc") == 0 && fileSize == 64) || ( strcmp(argv[4] , "xts") == 0 && fileSize == 16)){
        fprintf(stderr, "The required mod does not support the actual size of the key \n" );
        exit(1);
    }

    if(strcmp(argv[5],"null") != 0 && strcmp(argv[5],"plain") != 0 && strcmp(argv[5],"plain64") != 0 &&
            strcmp(argv[5],"essiv") != 0 && strcmp(argv[5],"benbi") != 0){
        fprintf(stderr, "Bad initialization vector\n" );
        exit(1);
    }
    char iv[strlen(argv[5])];
    strcpy(iv,argv[5]);

    if(strlen(argv[6]) != 1 || !(argv[6][0] == 'y' || argv[6][0] == 'n') ){
        fprintf(stderr, "A bad character or more characters were entered in the sixth parameter\n" );
        exit(1);
    }
    char allFile=argv[6][0];

    int sectorFrom = 0;
    int sectorTo = 0;
    if(allFile == 'n'){
         sectorFrom=argv[7][0];
         sectorTo=argv[8][0];
    }
    if(sectorFrom > sectorTo && sectorTo != 0){
        fprintf(stderr, "Bad range of sectors \n" );
        exit(1);
    }

    FILE * output;
    output=fopen("output.img","wb");
    if(output == NULL){
        fprintf(stderr, "Failed to create file\n" );
        exit(1);
    }

    if(strcmp(mode,"cbc") == 0){
        cbcEncryption(inputFile, output,key,fileSize,encryption,iv,sectorFrom,sectorTo);
    }
    if(strcmp(mode,"xts") == 0){
        xtsEncryption(inputFile,output,key,fileSize,encryption,iv,sectorFrom,sectorTo);
    }

    fclose(inputFile);
    fclose(output);

    if(encryption == 'e'){
        printf("Encryption succeeded. The output file is output.img\n");
    }else{
        printf("Decryption succeeded. The output file is output.img\n");
    }
    return 0;
}
