#include <NTL/ZZ.h>
#include <NTL/BasicThreadPool.h>
#include <NTL/lzz_pXFactoring.h>
#include "FHE.h"
#include "timing.h"
#include "EncryptedArray.h"
#include "FHE_operation.h"

#include <cassert>
#include <cstdio>
#include <iostream>
using namespace std;

int main()
{
	long m = 0;          // 确定系数
	long p = 2147483647; // 模量(素数)，定义超过p/2的数为负数，负数的真值x=D[E[x]]-p
	long r = 1;
	long L = 16;
	long c = 3;
	long w = 64;
	long d = 0;
	long k = 128;
	long s = 0;

	m = FindM(k, L, c, p, d, s, 0);

	FHEcontext context(m, p, r);
	buildModChain(context, L, c);
	ZZX G = context.alMod.getFactorsOverZZ()[0];
	
	// 生成公钥
	FHESecKey secretKey(context);
	const FHEPubKey& publicKey = secretKey;
	secretKey.GenSecKey(w);

	// 初始化密文
	Ctxt Ea(publicKey);
	Ctxt Eb(publicKey);

	// Test	
	long op1[5] = {2, 4, 0, 25, 15};
	long op2[5] = {-1, 1, 4, 0, 2};
	long *res;
	
	Vec<ZZ> h1 = arr2validVec(op1, 5);
	Vec<ZZ> h2 = arr2validVec(op2, 5);

	publicKey.Encrypt(Ea, to_ZZX(h1));
	publicKey.Encrypt(Eb, to_ZZX(h2));

	ZZX ptSum;
	secretKey.Decrypt(ptSum, FHE_Add(Ea, Eb));
	res = FHE_ptDec(ptSum, p, 5);
	cout << "ptSum : " << endl;
	for (int i=0; i<5; i++)
		cout << res[i] << " ";
	cout << endl;
	
	ZZX ptMul;
	secretKey.Decrypt(ptMul, FHE_Mul(Ea, Eb, p, publicKey, secretKey, 5));
	res = FHE_ptDec(ptMul, p, 5);
	cout << "ptMul : " << endl;
	for (int i=0; i<5; i++)
		cout << res[i] << " ";
	cout << endl;

	ZZX ptSub;
	secretKey.Decrypt(ptSub, FHE_Sub(Ea, Eb, p, publicKey, secretKey, 5));
	res = FHE_ptDec(ptSub, p, 5);
	cout << "ptSub : " << endl;
	for (int i=0; i<5; i++)
		cout << res[i] << " ";
	cout << endl;

	ZZX ptDiv;
	secretKey.Decrypt(ptDiv, FHE_Div(Ea, Eb, p, publicKey, secretKey, 5));
	res = FHE_ptDec(ptDiv, p, 5);
	cout << "ptDiv : " << endl;
	for (int i=0; i<5; i++)
		cout << res[i] << " ";
	cout << endl;

	return 0;
}