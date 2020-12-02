//RSA Public-Key Encryption and Signature Lab
//Task 5: Verifying a Signature

#include <stdio.h>
#include <openssl/bn.h>

#define NBITS 256

//function to print big number result
void printBN(char *msg, BIGNUM *a)
{
    //cast big number to char format
    char *number_str = BN_bn2hex(a);
    //print message and big number
    printf("%s %s\n", msg, number_str);
    //free big number
    OPENSSL_free(number_str);
}

int main()
{
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *e = BN_new();
    BIGNUM *n = BN_new();
    BIGNUM *S = BN_new();
    BIGNUM *M = BN_new();
    BIGNUM *message = BN_new();

    //initialize e, n, S, M
    BN_hex2bn(&e, "010001");
    printBN("e = ", e);
    BN_hex2bn(&n, "AE1CD4DC432798D933779FBD46C6E1247F0CF1233595113AA51B450F18116115");
    printBN("n = ", n);
    BN_hex2bn(&S, "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6802F");
    printBN("S = ", S);
    BN_hex2bn(&M, "4c61756e63682061206d697373696c652e");
    printBN("M = ", M);

    //decrypt ciphertext C with signature
    //message = S^e mod n

    //calculate M
    BN_mod_exp(message, S, e, n, ctx);
    printBN("message decrypted from signature is ", message);
    printBN("matches M before encryption ", M);

    return 0;
}