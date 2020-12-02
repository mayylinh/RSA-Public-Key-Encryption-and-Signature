//RSA Public-Key Encryption and Signature Lab
//Task 4: Signing a Message

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
    BIGNUM *M1 = BN_new();
    BIGNUM *M2 = BN_new();
    BIGNUM *d = BN_new();
    BIGNUM *S1 = BN_new();
    BIGNUM *S2 = BN_new();

    //initialize e, n, M1, M2, d
    BN_hex2bn(&e, "010001");
    printBN("e = ", e);
    BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
    printBN("n = ", n);
    BN_hex2bn(&M1, "49206f776520796f752024323030302e");
    printBN("M1 in ASCII = I owe you $2000.\nM1 in hex = ", M1);
    BN_hex2bn(&M2, "49206f776520796f752024333030302e");
    printBN("M2 in ASCII = I owe you $3000.\nM2 in hex = ", M2);
    BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");
    printBN("d = ", d);

    //encrypt message M with signature
    //C = M^d mod n

    //calculate C1 and C2
    BN_mod_exp(S1, M1, d, n, ctx);
    BN_mod_exp(S2, M2, d, n, ctx);
    printBN("signature for M1 is ", S1);
    printBN("signature for M2 is ", S2);

    return 0;
}