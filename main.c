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
 * @funkcia pocita logaritmus
 * @parameter x je cislo z ktoreho je pocitany
 * @navratova hodnota je logartmus z cisla x
 */
static int int_log2(unsigned int x)
{
    int r = 0;
    for (x >>= 1; x > 0; x >>= 1)
        r++;
    return r;
}
/**
 * @funkcia nastavuje parametru initialVector cislo sektora ako hodnotu
 * @parameter initialVector je 32 bitove cislo
 * @parameter sector je cislo sektora
 */
void increaseVector32(unsigned char * initialVector, int sector){
    for(int i = 0; i != BLOCK_SIZE/2-1 ; ++i){
          initialVector[i] = sector & 0xFF;
          sector = sector >> 8;
    }
}
/**
 * @funkcia nastavuje parametru initialVector cislo sektora ako hodnotu
 * @parameter initialVector je 64 bitove cislo
 * @parameter sector je cislo sektora
 */
void increaseVector64(unsigned char * initialVector, int sector){
    for(int i = 0; i != BLOCK_SIZE-1 ; ++i){
          initialVector[i] = sector & 0xFF;
          sector = sector >> 8;
    }
}
/**
 * @funkcia nastavuje benbi vektor
 * @parameter initialVector je 64 bitove cislo
 * @parameter sector je cislo sektora
 */
void setBenbiIV(unsigned char * initialVector, int sector){
    for(int i = BLOCK_SIZE-1; i != 0 ; --i){
          initialVector[i] = sector & 0xFF;
          sector = sector >> 8;
    }
}
/**
 * @funkcia nacitava kluc zo suboru
 * @parameter key je parameter do ktoreho sa nacitava kluc
 * @parameter keyFile obsahuje cestu k suboru
 * @parameter size je velkost kluca ktory ma byt nacitany
 */
void loadKey(unsigned char* key, char* keyFile, int size){
    FILE * file_key = fopen(keyFile,"rb");
    if(file_key == NULL){
        fprintf(stderr, "Subor s klucom sa nepodarilo otvorit\n" );
        exit(1);
    }
    if(fread(key,size,1,file_key) != 1 ){
        fprintf(stderr, "Chyba pocas nacitavania kluca\n");
        exit(1);
    }
    return ;
}
/**
 * @funkcia nastavuje inicializacny vektor
 * @parameter nameOfIV je nazov inicializacneho vektora
 * @parameter initialVector je inicializacny vektor
 * @parameter sector je cislo sektora na disku
 * @parameter key_hash je potrebny pri nastaveni vektora essiv, obsahuje zahasovany kluc funkciou SHA256
 * @parameter benbi_shift je hodnota posunu pre benbi vektor
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
 * @funkcia zahasuje kluc hasovaciou funkciou SHA256
 * @parameter keyStr je retazec obsahujuci kluc
 * @parameter size je velkost kluca
 * @parameter key_hash je vystupny parameter v ktorom po skonceni funkcie bude zahasovany kluc
 */
void SHA256hashing(unsigned char * keyStr, int size, AES_KEY *key_hash){
    unsigned char hash_key[2*BLOCK_SIZE];
    SHA256_CTX sha_key;
    SHA256_Init(&sha_key);
    SHA256_Update(&sha_key, keyStr, size);
    SHA256_Final(hash_key, &sha_key);
    AES_set_encrypt_key(hash_key,256,key_hash);
}
/**
 * @funkcia sifruje alebo desifruje obraz disku pomocou sifry AES-CBC
 * @parameter inputFile je vstupny subor ktory sa ma sifrovat alebo desifrovat
 * @parameter output je vystupny subor po spracovani suboru inputFile
 * @parameter keyStr je retazec obsahujuci kluc
 * @parameter enc je znak toho ci sa ma vstupny subor sifrovat alebo desifrovat
 * @parameter iv je nazov inicializacneho vektora
 * @parameter sizeFrom je cislo sektora od ktoreho sa ma zacat sifrovat alebo desifrovat
 * @parameter sizeTo je cislo sektora po ktory ma prebehnut sifrovanie alebo desifrovanie
 */
void cbcEncryption(FILE* inputFile,FILE* output, unsigned char* keyStr, char enc, char *iv, int sizeFrom, int sizeTo ){
    unsigned char *block = (unsigned char*) malloc(SECTOR_SIZE);
    unsigned char *out_block = (unsigned char*) malloc(SECTOR_SIZE);
    unsigned char* initialVector;

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
        AES_set_encrypt_key(keyStr,256,&key);
    }
    if(enc == 'd'){
        AES_set_decrypt_key(keyStr,256,&key);
    }

    if(strcmp(iv,"essiv") == 0){
        SHA256hashing(keyStr,2*BLOCK_SIZE,&key_hash);
    }

    int benbi_shift;
    if(strcmp(iv,"benbi") == 0){
      int log = int_log2(BLOCK_SIZE);
      if(log > SECTOR_SHIFT){
          fprintf(stderr, "Log je vacsi ako posun\n" );
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

        if(fwrite(out_block,SECTOR_SIZE,1,output) != 1) break;
        ++sector;
        if(sector == INT_MAX || (sector > sizeTo && sizeTo != 0)) break;

    }
    free(block);
    free(out_block);
    free(initialVector);    
}
/**
 * @funkcia sifruje alebo desifruje obraz disku pomocou sifry AES-XTS
 * @parameter inputFile je vstupny subor ktory sa ma sifrovat alebo desifrovat
 * @parameter output je vystupny subor po spracovani suboru inputFile
 * @parameter keyStr je retazec obsahujuci kluc
 * @parameter enc je znak toho ci sa ma vstupny subor sifrovat alebo desifrovat
 * @parameter iv je nazov inicializacneho vektora
 * @parameter sizeFrom je cislo sektora od ktoreho sa ma zacat sifrovat alebo desifrovat
 * @parameter sizeTo je cislo sektora po ktory ma prebehnut sifrovanie alebo desifrovanie
 */
void xtsEncryption(FILE* inputFile,FILE* output, unsigned char* keyStr, char enc, char *iv, int sizeFrom, int sizeTo){
    unsigned char *block = (unsigned char*) malloc(SECTOR_SIZE);
    unsigned char *out_block = (unsigned char*) malloc(SECTOR_SIZE);
    unsigned char* initialVector;

    if(strcmp(iv,"plain") == 0){
        initialVector = (unsigned char*) malloc(BLOCK_SIZE/2);
        memset(initialVector,0,BLOCK_SIZE/2);
    }else{
        initialVector = (unsigned char*) malloc(BLOCK_SIZE);
        memset(initialVector,0,BLOCK_SIZE);
    }

    AES_KEY key_hash;
    if(strcmp(iv,"essiv") == 0){
        SHA256hashing(keyStr,2*BLOCK_SIZE,&key_hash);
    }

    int benbi_shift;
    if(strcmp(iv,"benbi") == 0){
      int log = int_log2(BLOCK_SIZE);
      if(log > SECTOR_SHIFT){
          fprintf(stderr, "Log je vacsi ako posun\n" );
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
    free(initialVector);
    free(block);
    free(out_block);    
}

int main(int argc, char *argv[]){

    if(argc != 7 && argc != 9){
        fprintf(stderr, "Nespravny pocet parametrov\n" );
        exit(1);
    }

    FILE * inputFile;
    inputFile = fopen(argv[1],"rb");
    if(inputFile == NULL){
        fprintf(stderr, "Subor sa nepodarilo otvorit\n" );
        exit(1);
    }

    unsigned char key[2*BLOCK_SIZE];
    loadKey(key,argv[2],2*BLOCK_SIZE);

    if(strlen(argv[3]) != 1 || !(argv[3][0] == 'e' || argv[3][0] == 'd') ){
        fprintf(stderr, "Bol zadany zly znak alebo viac znakov v tretom parametri\n" );
        exit(1);
    }
    char encryption=argv[3][0];

    if(strlen(argv[4]) != 3 || !(strcmp(argv[4] , "cbc") == 0 || strcmp(argv[4] , "xts") == 0)){
        fprintf(stderr, "Zle zadany mod\n" );
        exit(1);
    }
    char mode[strlen(argv[4])];
    strcpy(mode,argv[4]);

    if(strcmp(argv[5],"null") != 0 && strcmp(argv[5],"plain") != 0 && strcmp(argv[5],"plain64") != 0 &&
            strcmp(argv[5],"essiv") != 0 && strcmp(argv[5],"benbi") != 0){
        fprintf(stderr, "Zle zadany inicializacny vektor\n" );
        exit(1);
    }
    char iv[strlen(argv[5])];
    strcpy(iv,argv[5]);

    if(strlen(argv[6]) != 1 || !(argv[6][0] == 'y' || argv[6][0] == 'n') ){
        fprintf(stderr, "Bol zadany zly znak alebo viac znakov v siestom parametri\n" );
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
        fprintf(stderr, "Zle zadane rozmedzie sektorov \n" );
        exit(1);
    }

    FILE * output;
    output=fopen("output.img","wb");
    if(output == NULL){
        fprintf(stderr, "Subor sa nepodarilo vytvorit\n" );
        exit(1);
    }

    if(strcmp(mode,"cbc") == 0){
        cbcEncryption(inputFile, output,key,encryption,iv,sectorFrom,sectorTo);
    }
    if(strcmp(mode,"xts") == 0){
        xtsEncryption(inputFile,output,key,encryption,iv,sectorFrom,sectorTo);
    }
    fclose(inputFile);
    fclose(output);

    if(encryption == 'e'){
        printf("Sifrovanie prebehlo uspesne. Vysledkom je subor output.img\n");
    }else{
        printf("Desifrovanie prebehlo uspesne. Vysledkom je subor output.img\n");
    }
    return 0;
}

