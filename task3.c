//RSA Public-Key Encryption and Signature Lab
//Task 3: Decrypting a Message

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
    BIGNUM *C = BN_new();
    BIGNUM *d = BN_new();
    BIGNUM *M = BN_new();

    //initialize n, C, d
    BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
    printBN("n = ", n);
    BN_hex2bn(&C, "8C0F971DF2F3672B28811407E2DABBE1DA0FEBBBDFC7DCB67396567EA1E2493F");
    printBN("C = ", C);
    BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");
    printBN("d = ", d);

    //decrypt ciphertext to get message M
    //M = C^d mod n

    //calculate M
    BN_mod_exp(M, C, d, n, ctx);
    printBN("decrypted message is ", M);

    return 0;
}
