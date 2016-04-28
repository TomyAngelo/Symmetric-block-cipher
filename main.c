#include <stdio.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/modes.h>
#include <openssl/evp.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define BLOCK_SIZE 16
#define SECTOR_SIZE 512
#define SECTOR_SHIFT 9

static int int_log2(unsigned int x)
{
    int r = 0;
    for (x >>= 1; x > 0; x >>= 1)
        r++;
    return r;
}

void increaseVector32(unsigned char * initialVector, int sector){
    for(int i = 0; i != BLOCK_SIZE/2-1 ; ++i){
          initialVector[i]=sector & 0xFF;
          sector=sector>>8;
    }
}
void increaseVector64(unsigned char * initialVector, int sector){
    for(int i = 0; i != BLOCK_SIZE-1 ; ++i){
          initialVector[i]=sector & 0xFF;
          sector=sector>>8;
    }
}

void setBenbiIV(unsigned char * initialVector, int sector){
    for(int i = BLOCK_SIZE-1; i != 0 ; --i){
          initialVector[i]=sector & 0xFF;
          sector=sector>>8;
    }
}

void loadKey(unsigned char* key,char* keyFile,int size){
    FILE * file_key=fopen(keyFile,"rb");
    if(file_key==NULL){
        fprintf(stderr, "Subor s klucom sa nepodarilo otvorit\n" );
        exit(1);
    }
    if(fread(key,size,1,file_key) != 1 ){
        fprintf(stderr, "Chyba pocas nacitavania kluca\n");
        exit(1);
    }
    return ;
}

char* parseString(char* input){
    int d=strlen(input);
    if(d<2){
        fprintf(stderr, "Nebola zadana ziadna hodnota\n");
        exit(1);
    }
    input[d-1]='\0';
    return input;
}

void setInitialVector(char * nameOfIV,unsigned char * initialVector, int sector, AES_KEY *key_hash,int benbi_shift ){
    if(strcmp(nameOfIV,"plain")== 0){
        memset(initialVector,0,BLOCK_SIZE/2);
    }else{
        memset(initialVector,0,BLOCK_SIZE);
    }

    if(strcmp(nameOfIV,"plain")== 0){
        increaseVector32(initialVector,sector);
    }
    if(strcmp(nameOfIV,"plain64")== 0){
        increaseVector64(initialVector,sector);
    }
    if(strcmp(nameOfIV,"essiv")== 0){
        increaseVector64(initialVector,sector);
        AES_ecb_encrypt(initialVector,initialVector,key_hash,AES_ENCRYPT);
    }
    if(strcmp(nameOfIV,"benbi")== 0){
        setBenbiIV(initialVector,(sector << benbi_shift)+1);
    }
}

void cbcEncryption(FILE* inputFile,FILE* output, unsigned char* keyStr, char enc, char *iv,int sizeFrom,int sizeTo ){
    unsigned char *block = (unsigned char*) malloc(SECTOR_SIZE);
    unsigned char *out_block = (unsigned char*) malloc(SECTOR_SIZE);
    unsigned char* tempvector=(unsigned char*) malloc(BLOCK_SIZE);
    unsigned char* initialVector;

    if(strcmp(iv,"plain")== 0){
        initialVector = (unsigned char*) realloc(tempvector,(BLOCK_SIZE/2* sizeof(unsigned char)));
        memset(initialVector,0,BLOCK_SIZE/2);
    }else{
        initialVector = (unsigned char*) realloc(tempvector,(BLOCK_SIZE* sizeof(unsigned char)));
        memset(initialVector,0,BLOCK_SIZE);
    }

    AES_KEY key;
    AES_KEY key_hash;

    if(enc == 'e'){
        AES_set_encrypt_key(keyStr,256,&key);
    }
    if(enc == 'd'){
        AES_set_decrypt_key(keyStr,256,&key);
    }

    if(strcmp(iv,"essiv")==0){
        unsigned char hash_key[2*BLOCK_SIZE];
        SHA256_CTX sha_key;
        SHA256_Init(&sha_key);
        SHA256_Update(&sha_key, keyStr, 2*BLOCK_SIZE);
        SHA256_Final(hash_key, &sha_key);
        AES_set_encrypt_key(hash_key,256,&key_hash);
    }
    int benbi_shift;
    if(strcmp(iv,"benbi")==0){
      int log=int_log2(BLOCK_SIZE);
      if(log > SECTOR_SHIFT){
          fprintf(stderr, "Log je vacsi ako posun\n" );
          exit(1);
      }
      benbi_shift=SECTOR_SHIFT-log;
    }

    int sector=0;
    while(sector < sizeFrom){
        fread(block,SECTOR_SIZE,1,inputFile);
        //if(fwrite(block,SECTOR_SIZE,1,output)!= 1) break; //maybe
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

        if(fwrite(out_block,SECTOR_SIZE,1,output)!= 1) break;

        ++sector;
        if(sector == INT_MAX || (sector > sizeTo && sizeTo != 0)) break;

    }
    free(block);
    free(out_block);
    free(initialVector);
    fclose(output);
}

void xtsEncryption(FILE* inputFile,FILE* output, unsigned char* keyStr, char enc, char *iv,int sizeFrom,int sizeTo){

    unsigned char *block = (unsigned char*) malloc(SECTOR_SIZE);
    unsigned char *out_block = (unsigned char*) malloc(SECTOR_SIZE);
    unsigned char* tempvector=(unsigned char*) malloc(BLOCK_SIZE);
    unsigned char* initialVector;

    if(strcmp(iv,"plain")== 0){
        initialVector = (unsigned char*) realloc(tempvector,(BLOCK_SIZE/2* sizeof(unsigned char)));
        memset(initialVector,0,BLOCK_SIZE/2);
    }else{
        initialVector = (unsigned char*) realloc(tempvector,(BLOCK_SIZE* sizeof(unsigned char)));
        memset(initialVector,0,BLOCK_SIZE);
    }

    AES_KEY key_hash;

    if(strcmp(iv,"essiv")==0){
        unsigned char hash_key[2*BLOCK_SIZE];
        SHA256_CTX sha_key;
        SHA256_Init(&sha_key);
        SHA256_Update(&sha_key, keyStr, 2*BLOCK_SIZE);
        SHA256_Final(hash_key, &sha_key);
        AES_set_encrypt_key(hash_key,256,&key_hash);
    }
    int benbi_shift;
    if(strcmp(iv,"benbi")==0){
      int log=int_log2(BLOCK_SIZE);
      if(log > SECTOR_SHIFT){
          fprintf(stderr, "Log je vacsi ako posun\n" );
          exit(1);
      }
      benbi_shift=SECTOR_SHIFT-log;
    }

    EVP_CIPHER_CTX *ctx;
    int len;

    int sector=0;
    while(sector < sizeFrom){
        fread(block,SECTOR_SIZE,1,inputFile);
        ++sector;
    }

    setInitialVector(iv,initialVector,sector,&key_hash,benbi_shift);

    while (fread(block,SECTOR_SIZE,1,inputFile) == 1){
        ctx = EVP_CIPHER_CTX_new();

        setInitialVector(iv,initialVector,sector,&key_hash,benbi_shift);
        if(enc == 'e'){
            EVP_EncryptInit_ex(ctx, EVP_aes_128_xts(), NULL, keyStr, initialVector);
            EVP_EncryptUpdate(ctx, out_block, &len, block, SECTOR_SIZE);
            EVP_EncryptFinal_ex(ctx, out_block + len, &len);
        }else if(enc == 'd'){
            EVP_DecryptInit_ex(ctx, EVP_aes_128_xts(), NULL, keyStr, initialVector);
            EVP_DecryptUpdate(ctx, out_block, &len, block, SECTOR_SIZE);
            EVP_DecryptFinal_ex(ctx, out_block + len, &len);
        }
        if(fwrite(out_block,SECTOR_SIZE,1,output) != 1) break ;

        ++sector;
        if(sector == INT_MAX || (sector > sizeTo && sizeTo != 0)) break;
    }

    EVP_CIPHER_CTX_free(ctx);
    free(block);
    free(out_block);
    fclose(output);
}

int main(void)
{
    if(INT_MAX < 2048) puts("WHAT!!!!!??");
    puts("Zadajte cestu k suboru: ");
    char pathToFile[255];
    fgets(pathToFile,255,stdin);
    char fileName[strlen(pathToFile)];
    strcpy(fileName , parseString(pathToFile) );
    FILE * inputFile;
    inputFile=fopen(fileName,"rb");
    if(inputFile==NULL){
        fprintf(stderr, "Subor sa nepodarilo otvorit\n" );
        exit(1);
    }

    puts("Zadajte cestu ku klucu: ");
    char pathToKey[255];
    fgets(pathToKey,255,stdin);
    char keyName[strlen(pathToKey)];
    strcpy(keyName , parseString(pathToKey) );
    unsigned char key[2*BLOCK_SIZE];
    loadKey(key,keyName,2*BLOCK_SIZE);


    puts("Chcete sifrovat[e] alebo desifrovat[d] ? ");
    char tempEncryption[10];
    fgets(tempEncryption,10,stdin);
    if(strlen(tempEncryption)> 2 || !(tempEncryption[0] =='e' || tempEncryption[0] =='d') ){
        fprintf(stderr, "Bol zadany zly znak alebo viac znakov\n" );
        exit(1);
    }
    char encryption=tempEncryption[0];

    puts("Zadajte mod ktory ma byt pouzity: CBC[cbc] alebo XTS[xts]? ");
    char tempMode[10];
    fgets(tempMode,10,stdin);
    if(strlen(tempMode) != 4){
        fprintf(stderr, "Zle zadany mod\n" );
        exit(1);
    }
    char mode[strlen(tempMode)];
    strcpy(mode,parseString(tempMode));
    if(strcmp(mode,"cbc") != 0 && strcmp(mode,"xts") != 0){
        fprintf(stderr, "Zle zadany mod\n" );
        exit(1);
    }


    puts("Zadajte inicializacny vektor ktory ma byt pouzity: \n null\n plain\n plain64\n essiv\n benbi\n");
    char tempIv[10];
    fgets(tempIv,10,stdin);
    char iv[strlen(tempIv)];
    strcpy(iv,parseString(tempIv));
    if(strcmp(iv,"null") != 0 && strcmp(iv,"plain") != 0 && strcmp(iv,"plain64") != 0 &&
            strcmp(iv,"essiv") != 0 && strcmp(iv,"benbi") != 0){
        fprintf(stderr, "Zle zadany inicializacny vektor\n" );
        exit(1);
    }


    puts("Chcete sifrovat/desifrovat cely subor? [y]/[n]");
    char allFile;
    scanf("%c",&allFile);
    if(allFile != 'y' && allFile != 'n'){
        fprintf(stderr, "Zly znak bol zadany\n" );
        exit(1);
    }
    int sectorFrom=0;
    int sectorTo=0;
    if(allFile == 'n'){
        puts("Zadajte rozmedzie sektorov: (napr. 1024 4096)");
        scanf("%d %d",&sectorFrom,&sectorTo);
    }
    if(sectorFrom > sectorTo && sectorTo != 0){
        fprintf(stderr, "Zle zadane rozmedzie sektorov \n" );
        exit(1);
    }

    FILE * output;
    output=fopen("output.img","wb");
    if(inputFile==NULL){
        fprintf(stderr, "Subor sa nepodarilo vytvorit\n" );
        exit(1);
    }


    if(strcmp(mode,"cbc")==0){
        cbcEncryption(inputFile, output,key,encryption,iv,sectorFrom,sectorTo);
    }
    if(strcmp(mode,"xts")==0){
        xtsEncryption(inputFile,output,key,encryption,iv,sectorFrom,sectorTo);
    }

    printf("Sifrovanie/desifrovanie prebehlo uspesne. Vysledkom je subor output.img\n");
    return 0;
}

