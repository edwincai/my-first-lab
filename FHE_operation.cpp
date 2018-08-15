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

/*  下面两个函数的作用是把数字或者数组转为可用于运算操作的vector
 *  因为当加密和解密过后，最后连续的n个0会被隐藏
 *  例如[2 2 0 0]→[2 2], [0 0 0 0]→[]
 *  []转为long输出时会出错，所以在末尾加上1使得0可以正确地被提取出来
 */

// 数字转为可用于运算操作的vector
Vec<ZZ> num2validVec(long num)
{
	Vec<ZZ> v;
	v.SetLength(2);
	v[0] = num;
	v[1] = 1;
	return v;
}

// 数组转为可用于运算操作的vector
Vec<ZZ> arr2validVec(long* num, int arrLen)
{
	Vec<ZZ> v;
	v.SetLength(arrLen+1);
	for (int i=0; i<arrLen; i++)
		v[i] = num[i];
	v[arrLen] = 1;
	return v;
}

// 四则运算全同态解密（只实现了数字作为运算符的解密，数组作为运算符的有待修缮）
long FHE_ptDec(ZZX ptxt, long p)
{
	long ptDec;
	conv(ptDec, ptxt[0]);
	if (ptDec > p/2)
		ptDec -= p;
	return ptDec;
}

// 全同态加法
Ctxt FHE_Add(Ctxt Ea, Ctxt Eb)
{
	Ctxt ctSum = Ea;
	ctSum += Eb;
	return ctSum;
}

// 全同态乘法
Ctxt FHE_Mul(Ctxt Ea, Ctxt Eb, long p, const FHESecKey& secretKey)
{
	ZZX ptEa, ptEb;
	secretKey.Decrypt(ptEa, Ea);
	secretKey.Decrypt(ptEb, Eb);
	// 解密判断乘数中是否有0，如果是，则返回0的密文
	if (FHE_ptDec(ptEa, p) == 0)
		return Ea;
	else if (FHE_ptDec(ptEb, p) == 0)
		return Eb;
	else
	{
		Ctxt ctMul = Ea;
		ctMul *= Eb;
		return ctMul;
	}
}

// 全同态减法
Ctxt FHE_Sub(Ctxt Ea, Ctxt Eb, const FHEPubKey& publicKey)
{
	// sub = op2*(-1)+op1
	Ctxt minus1(publicKey);
	Vec<ZZ> m1 = num2validVec(-1);
	publicKey.Encrypt(minus1, to_ZZX(m1));
	Ctxt ctSub = Eb;
	ctSub *= minus1;
	ctSub += Ea;
	return ctSub;
}

// 全同态除法
Ctxt FHE_Div(Ctxt Ea, Ctxt Eb, long p,
			 const FHEPubKey& publicKey, const FHESecKey& secretKey)
{
	int quotient = 0;  // 初始化商quotient为0
	ZZX ptMul, ptMul2, ptSub, ptSum, ptEa, ptEb;

	/* 判断思路（设被除数和除数为op1和op2）：
	 * 1. op2=0时，输出"Error: Invalid Denominator."，否则继续
	 * 2. op1=0时，返回0的密文，否则继续
	 * 3. 判断op1和op2是否同号,可用op1·op2是否为正来判断
	 *    3-1. 同号: 当op1=0时跳出循环，否则
	 *               sub=op1-op2，如果sub和op1同号(op1和op2同为负数的时候sub也是负数)则quotient递增且op1=sub，否则跳出循环
	 *    3-2. 异号: 当op1=0时跳出循环，否则
	 *               sum=op1+op2(因为是异号)，如果sum和op1同号则quotient递减(异号相除结果为负数)且op1=sum，否则跳出循环        
	 */
	bool positive = true;
	secretKey.Decrypt(ptEa, Ea);
	long EaDec = FHE_ptDec(ptEa, p);
	if(EaDec < 0) positive = false;
	secretKey.Decrypt(ptEb, Eb);
	long EbDec = FHE_ptDec(ptEb, p);
	if (EbDec == 0) 
	{
		cout << "Error: Invalid Denominator." << endl;
		Ctxt ctDiv(publicKey);
		Vec<ZZ> q = num2validVec(quotient);
		publicKey.Encrypt(ctDiv, to_ZZX(q));
		return ctDiv;
	}
	else if (EaDec == 0)
	{
		Ctxt ctDiv(publicKey);
		Vec<ZZ> q = num2validVec(quotient);
		publicKey.Encrypt(ctDiv, to_ZZX(q));
		return ctDiv;
	}
	else {
		secretKey.Decrypt(ptMul, FHE_Mul(Ea, Eb, p, secretKey));
		// 两操作数同号
		if(FHE_ptDec(ptMul, p) >= 0)
		{
			while (1)
			{
				secretKey.Decrypt(ptEa, Ea);
				long EaDec = FHE_ptDec(ptEa, p);
				if (EaDec == 0) break;
				else
				{
					Ctxt ctSub = FHE_Sub(Ea, Eb, publicKey);
					secretKey.Decrypt(ptSub, ctSub);
					long sub = FHE_ptDec(ptSub, p);
					if (sub >= 0 && positive || sub <= 0 && !positive)
					{
						Ea = ctSub;
						quotient ++;
					}
					else break;
				}
			}
		}
		// 两操作数异号 
		else 
		{
			while (1)
			{
				secretKey.Decrypt(ptEa, Ea);
				long EaDec = FHE_ptDec(ptEa, p);
				if (EaDec == 0) break;
				else
				{
					Ctxt ctSum = FHE_Add(Ea, Eb);
					secretKey.Decrypt(ptMul2, FHE_Mul(ctSum, Ea, p, secretKey));
					long temp = FHE_ptDec(ptMul2, p);
					if (temp >= 0)
					{
						Ea = ctSum;
						quotient --;
					}
					else break;
				}
			}
		}
		Ctxt ctDiv(publicKey);
		Vec<ZZ> q = num2validVec(quotient);
		publicKey.Encrypt(ctDiv, to_ZZX(q));
		return ctDiv;
	}
}



int main()
{
	long m = 0;    // 确定系数
	long p = 1021; // 模量，定义超过p/2的数为负数，负数的真值x=D[E[x]]-p
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

	/* Test: 输入两个不全为0的数，输出四则运算结果，输入两个0可退出	*/
	long op1, op2;
	while (!(op1==0 && op2==0))
	{
		cin >> op1 >> op2;
		Vec<ZZ> h1 = num2validVec(op1);
		Vec<ZZ> h2 = num2validVec(op2);

		publicKey.Encrypt(Ea, to_ZZX(h1));
		publicKey.Encrypt(Eb, to_ZZX(h2));

		cout << "Operator 1 : " << op1 << " , Operator 2 : " << op2 << endl;

		ZZX ptSum;
		secretKey.Decrypt(ptSum, FHE_Add(Ea, Eb));
		cout << "ptSum : " << FHE_ptDec(ptSum, p) << endl;
		
		ZZX ptMul;
		secretKey.Decrypt(ptMul, FHE_Mul(Ea, Eb, p, secretKey));
		cout << "ptMul : " << FHE_ptDec(ptMul, p) << endl;

		ZZX ptSub;
		secretKey.Decrypt(ptSub, FHE_Sub(Ea, Eb, publicKey));
		cout << "ptSub : " << FHE_ptDec(ptSub, p) << endl;

		ZZX ptDiv;
		secretKey.Decrypt(ptDiv, FHE_Div(Ea, Eb, p, publicKey, secretKey));
		cout << "ptDiv : " << FHE_ptDec(ptDiv, p) << endl;
	}

	return 0;
}