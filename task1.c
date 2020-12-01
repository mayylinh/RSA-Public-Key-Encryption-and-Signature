//RSA Public-Key Encryption and Signature Lab
//Task 1: Deriving Private Key

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
	BIGNUM *p = BN_new();
	BIGNUM *q = BN_new();
	BIGNUM *e = BN_new();
	BIGNUM *one = BN_new();
	BIGNUM *pminus1 = BN_new();
	BIGNUM *qminus1 = BN_new();
	BIGNUM *phin = BN_new();
	BIGNUM *d = BN_new();

	//initalize p, q, e, one
	BN_hex2bn(&p, "F7E75FDC469067FFDC4E847C51F452DF");
	printBN("p = ", p);
	BN_hex2bn(&q, "E85CED54AF57E53E092113E62F436F4F");
	printBN("q = ", q);
	BN_hex2bn(&e, "0D88C3");
	printBN("e = ", e);
	BN_dec2bn(&one, "1");

	//calculate private key d
	//phi(n) = (p - 1)(q - 1)
	//e * d = 1 mod phi(n) and 0<=d<=n

	//calculate (p - 1)
	BN_sub(pminus1, p, one);
	printBN("(p - 1) = ", pminus1);
	//calculate (q - 1)
	BN_sub(qminus1, q, one);
	printBN("(q - 1) = ", qminus1);
	//calculate phi(n)
	BN_mul(phin, pminus1, qminus1, ctx);
	printBN("phi(n) = (p - 1)(q - 1) = ", phin);
	//calculate d
	BN_mod_inverse(d, e, phin, ctx);
	printBN("private key d is ", d);

	return 0;
}