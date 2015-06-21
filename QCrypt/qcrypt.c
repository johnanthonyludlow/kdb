/*

qcrypt is a set of wrapper functions allowing kdb+ to interface with openssl
cryptographic functions including 
1) Random number generation - qrand
2) hashing algorithms - md5, sha1, sha224, sha256, sha384, sha512 - hash
3) Key stretching - pbkdf2
 
Example compile line (change location and version of openssl library as appropriate):
 gcc -shared -fPIC qcrypt.c -o qcrypt.so -L ~/crypto/openssl-1.0.1f -I ~/crypto/openssl-1.0.1f/include -lssl -lcrypto -ldl  

Examples:
- Random number generation
q)qrand:`qcrypt 2: (`qrand;1)
q)qrand(5)
0xca69abd6f2
q)qrand(1)
,0x1c
q)qrand(3)
0xc33887
q)qrand(20)
0x18783509f5dad3459c4d5b2598ef529bb288bf1c

- Hashing  
q)hash:`qcrypt 2: (`hash;2)
q)\c 2000 2000
q)hash["testtest";"md5"]
0x05a671c66aefea124cc08b76ea6d30bb
q)hash["testtest";"sha1"]
0x51abb9636078defbf888d8457a7c76f85c8f114c
q)hash["testtest";"sha224"]
0xf617af1ca774ebbd6d23e8fe12c56d41d25a22d81e88f67c6c6ee0d4
q)hash["testtest";"sha256"]
0x37268335dd6931045bdcdf92623ff819a64244b53d0e746d438797349d4da578
q)hash["testtest";"sha384"]
0x40e1b690e9200dd972cb29f4526a1c6597eb9bbc06bd4a2650c34dd9424cbde0327d3f3d6898d8e456f91f21fb6805c6
q)hash["testtest";"sha512"]
0x125d6d03b32c84d492747f79cf0bf6e179d287f341384eb5d6d3197525ad6be8e6df0116032935698f99a09e265073d1d6c32c274591bf1d0a20ad67cba921bc

- Key Stretching 
q)pbkdf2:`qcrypt 2: (`pbkdf2;4)
q)pbkdf2["password";`byte$"salt";100;20]
0x8595d7aea0e7c952a35af9a838cc6b393449307c

*/

#include <string.h>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#define KXVER 3
#include "k.h"

K hash(K x,K y){
    int lenx,leny,i;
    lenx=x->n;
    leny=y->n;
    char message[lenx+1];
    char hashfunction[leny+1];
    if(10==(x->t)){
       for(i=0;i<lenx;i++){
          message[i]=kC(x)[i];
       }
       message[lenx]=0;
    }
    if(10==(y->t)){
       for(i=0;i<leny;i++){
          hashfunction[i]=kC(y)[i];
       }
       hashfunction[leny]=0;
    }

    int bytelength;
    unsigned char* (*foo)(const unsigned char*, size_t, unsigned char*);
    if(strcmp("sha1",hashfunction)==0){
        bytelength=SHA_DIGEST_LENGTH;
        foo=&SHA1;
    } else if(strcmp("sha224",hashfunction)==0){
        bytelength=SHA224_DIGEST_LENGTH;
        foo=&SHA224;
    } else if(strcmp("sha256",hashfunction)==0){
        bytelength=SHA256_DIGEST_LENGTH;
        foo=&SHA256;
    } else if(strcmp("sha384",hashfunction)==0){
        bytelength=SHA384_DIGEST_LENGTH;
        foo=&SHA384;
    } else if(strcmp("sha512",hashfunction)==0){
        bytelength=SHA512_DIGEST_LENGTH;
        foo=&SHA512;
    } else if(strcmp("md5",hashfunction)==0){
        bytelength=MD5_DIGEST_LENGTH;
        foo=&MD5;
    } else{
        krr("Please choose a supported hash function");
        return (K)0;
    }

    unsigned char result[bytelength];
    foo((unsigned char*) message, strlen(message), result);
    K output=ktn(KG,bytelength);
    for(i=0;i<bytelength;i++){
        kG(output)[i]=result[i];
    }

    return output;
}

K qrand(K x){
    int saltlength,i;
    saltlength=x->i;
    unsigned char salt[saltlength];
     
    if (RAND_bytes(salt,saltlength)==0){
        krr("Random number generation failure");
        return (K)0;
    }

    K output=ktn(KG,saltlength);
    for(i=0;i<saltlength;i++){
        kG(output)[i]=salt[i];
    }

    return output;
}

K pbkdf2(K qpassword,K qsalt,K qiterations, K qdklen){
        int iterations,dklen,passlen,saltlen,i,retv;
        passlen=qpassword->n;
        saltlen=qsalt->n;
        char password[passlen];
        unsigned char salt[saltlen];
        iterations=qiterations->i;
        dklen=qdklen->i;
        unsigned char result[dklen];

        if(10==(qpassword->t)){
           for(i=0;i<passlen;i++){
               password[i]=kC(qpassword)[i];
            }
            password[passlen]=0;
        }

        if(4==(qsalt->t)){
           for(i=0;i<saltlen;i++){
               salt[i]=kG(qsalt)[i];
            }
        } 
         
        retv=PKCS5_PBKDF2_HMAC_SHA1(password,strlen(password),salt,sizeof(salt),iterations,dklen,result); 

       if(retv==0){
              krr("PKCS5_PBKDF2_HMAC_SHA1 failed");
              return (K)0;
        }

       K output=ktn(KG,dklen);
       for(i=0;i<dklen;i++){
           kG(output)[i]=result[i];
        }

       return output;
}
