//RSA Public-Key Encryption and Signature Lab
//Task 2: Encrypting a Message

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
    BIGNUM *n = BN_new();
    BIGNUM *e = BN_new();
    BIGNUM *M = BN_new();
    BIGNUM *C = BN_new();
    BIGNUM *d = BN_new();
    BIGNUM *message = BN_new();

    //initialize n, e, M
    BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
    printBN("n = ", n);
    BN_hex2bn(&e, "010001");
    printBN("e = ", e);
    BN_hex2bn(&M, "4120746F702073656372657421");
    printBN("M in ASCII = A top secret!\nM in hex = ", M);

    //calculate ciphertext C
    //C = M^e mod n, where 0<=M<n

    //calculate C
    BN_mod_exp(C, M, e, n, ctx);
    printBN("ciphertext C is ", C);

    //verify C is correct
    BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");
    printBN("--verify encryption result--\nd = ", d);

    //decrypt ciphertext to get message M
    //M = C^d mod n

    //get M
    BN_mod_exp(message, C, d, n, ctx);
    printBN("decrypted message is ", message);
    printBN("matches M before encryption ", M);

    return 0;
}
