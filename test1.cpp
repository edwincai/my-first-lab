#include <NTL/ZZ.h>
#include <NTL/BasicThreadPool.h>
#include "FHE.h"
#include "timing.h"
#include "EncryptedArray.h"
#include <NTL/lzz_pXFactoring.h>

#include <cassert>
#include <cstdio>
#include <iostream>
using namespace std;

Ctxt FHE_Add(Ctxt Ea, Ctxt Eb)
{
	Ctxt ctSum = Ea;
	ctSum += Eb;
	return ctSum;
}

Ctxt FHE_Mul(Ctxt Ea, Ctxt Eb)
{
	Ctxt ctMul = Ea;
	ctMul *= Eb;
	return ctMul;
}

Ctxt FHE_Sub(Ctxt Ea, Ctxt Eb, const FHEPubKey& publicKey)
{
	Ctxt minus1(publicKey);
	publicKey.Encrypt(minus1, to_ZZX(-1));
	Ctxt ctSub = Eb;
	ctSub *= minus1;
	ctSub += Ea;
	return ctSub;
}

Ctxt FHE_Div(Ctxt Ea, Ctxt Eb, long p,
			 const FHEPubKey& publicKey, const FHESecKey& secretKey)
{
	int quotient = 0;
	bool flag = true;
	while (flag)
	{
		Ctxt ctSub = FHE_Sub(Ea, Eb, publicKey);
		ZZX ptSub;
		secretKey.Decrypt(ptSub, ctSub);
		long sub;
		conv(sub, ptSub[0]);
		if (sub <= p/2)
		{
			Ea = ctSub;
			quotient ++;
		}
		if (sub >= p/2)
			flag = false;
	}
	Ctxt ctDiv(publicKey);
	publicKey.Encrypt(ctDiv, to_ZZX(quotient));
	return ctDiv;
}

int main()
{
	long m = 0;    // 确定系数
	long p = 1021; // 2^64
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

	FHESecKey secretKey(context);
	const FHEPubKey& publicKey = secretKey;
	secretKey.GenSecKey(w);

	Ctxt Ea(publicKey);
	Ctxt Eb(publicKey);

	Vec<ZZ> h;
	h.SetLength(4);
	h[0]=2;
	h[1]=2;
	h[2]=0;
	h[3]=0;


	publicKey.Encrypt(Ea, to_ZZX(h));
	//publicKey.Encrypt(Eb, to_ZZX(2));

	ZZX ptEa;
	secretKey.Decrypt(ptEa, Ea);
	cout << "ptEa : " << ptEa <<endl;

/*
	ZZX ptSum;
	Ctxt ctSum = FHE_Add(Ea, Eb);
	secretKey.Decrypt(ptSum, ctSum);
	cout << "ptSum : " << ptSum <<endl;
	
	ZZX ptMul;
	Ctxt ctMul = FHE_Mul(Ea, Eb);
	secretKey.Decrypt(ptMul, ctMul);
	cout << "ptMul : " << ptMul <<endl;

	ZZX ptSub;
	secretKey.Decrypt(ptSub, FHE_Sub(Ea, Eb, publicKey));
	cout << "ptSub : " << ptSub <<endl;

	ZZX ptDiv;
	secretKey.Decrypt(ptDiv, FHE_Div(Ea, Eb, p, publicKey, secretKey));
	cout << "ptDiv : " << ptDiv <<endl;
*/
	return 0;
}