#include <NTL/ZZ.h>
#include <NTL/BasicThreadPool.h>
#include "FHE.h"
#include "timing.h"
#include "EncryptedArray.h"
#include <NTL/lzz_pXFactoring.h>

#include <cassert>
#include <cstdio>
#include <iostream>
#include <vector>
#include <bitset>
#include <string>
using namespace std;
Ctxt operator + (Ctxt left, Ctxt right)
{
	Ctxt temp(left);
	temp+=right;
	return temp;
}
Ctxt operator * (Ctxt left, Ctxt right)
{
	Ctxt temp(left);
	temp*=right;
	return temp;
}
int biggerThan(int plainText1, int plainText2)
{
	FHEcontext * context;
	FHESecKey *secretKey;
	const FHEPubKey * publicKey;
	long p = 2;
	long r = 1;
	long L = 16;
	long c = 3;
	long w = 64;
	long d = 0;
	long k = 128;
	long s = 0;

	long m = FindM(k, L, c, p, d, s, 0);
	unsigned bits =2;
	
	context = new FHEcontext(m, p, r);
	buildModChain(*context, L, c);

	ZZX G = context->alMod.getFactorsOverZZ()[0];
	
	secretKey = new FHESecKey(*context);
	publicKey = secretKey;
	secretKey->GenSecKey(w);

	//plain text
	vector<long> plainTextBinaryVector1(4, 0);
	vector<long> plainTextBinaryVector2(4, 0);

	//ciphertext
	vector<Ctxt> ctxtVector1(4, Ctxt(*publicKey));
	vector<Ctxt> ctxtVector2(4, Ctxt(*publicKey));

	//转换成二进制串
	bitset<4> b1(plainText1);
	bitset<4> b2(plainText2);

	for(int i=0; i<b1.size(); i++)
	{
		plainTextBinaryVector1[i]=b1[i];
		plainTextBinaryVector2[i]=b2[i];
	}

	for(int i=0; i<b1.size(); i++)
	{
		publicKey->Encrypt(ctxtVector1[i], to_ZZX(plainTextBinaryVector1[i]));
		publicKey->Encrypt(ctxtVector2[i], to_ZZX(plainTextBinaryVector2[i]));
	}

	//boolean circuit

	//1s
	Ctxt ctxtOne(*publicKey);
	publicKey->Encrypt(ctxtOne, to_ZZX(1));

	ZZX temp;
	Ctxt comparisionResult(*publicKey);
	publicKey->Encrypt(comparisionResult, to_ZZX(0));

	comparisionResult = ctxtVector1[3]*(ctxtVector2[3]+ctxtOne);
	// comparisionResult = ctxtVector1[3]*=(ctxtVector2[3]+=ctxtOne);
	secretKey->Decrypt(temp, comparisionResult);
	//cout<<"1:  "<<temp<<endl;

	comparisionResult = comparisionResult+ (ctxtVector1[3]+ctxtVector2[3]+ctxtOne)
	*ctxtVector1[2]*(ctxtVector2[2]+ctxtOne);
	//这里用XOR可以代替OR，因为运算表达式决定了两个加数不可能同时为1
	secretKey->Decrypt(temp, comparisionResult);
	//cout<<"2:  "<<temp<<endl;

	comparisionResult = comparisionResult + 
	(ctxtVector1[3]+ctxtVector2[3]+ctxtOne) *
	(ctxtVector1[2]+ctxtVector2[2]+ctxtOne) *
	ctxtVector1[1]*(ctxtVector2[1]+ctxtOne);
	secretKey->Decrypt(temp, comparisionResult);
	//cout<<"3:  "<<temp<<endl;

	comparisionResult = comparisionResult +
	(ctxtVector1[3]+ctxtVector2[3]+ctxtOne) *
	(ctxtVector1[2]+ctxtVector2[2]+ctxtOne) *
	(ctxtVector1[1]+ctxtVector2[1]+ctxtOne) *
	ctxtVector1[0]*(ctxtVector2[0]+ctxtOne);
	secretKey->Decrypt(temp, comparisionResult);
	//cout<<"4:  "<<temp<<endl;

	ZZX result;
	secretKey->Decrypt(result, comparisionResult);
	//cout<<"result : "<<result<<endl;
	long hh;
	conv(hh, result[0]);

	delete context;
	delete secretKey;

	return int(hh);
}
int main()
{
	for(int x=0; x<16; x++)
	{
		for(int y=0; y<16; y++)
		{
			cout<<"x  "<<x<<"y  "<<y<<endl;
			if(biggerThan(x, y) != (x>y))
			{
				cout<<"error!"<<endl;
				cout<<"biggerThan : "<<biggerThan(x,y)<<endl;
				cout<<"x>y: "<<(x>y)<<endl;
				return 0;
			}
		}
	}
	while(true)
	{
		int a;
		int b;
		cin>>a;
		cin>>b;
		cout<<biggerThan(a, b)<<endl;
	}
}