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

class Transaction
{
public:
	
	Transaction(int l) : length(l) {t = new int[l];}
	Transaction(const Transaction &tr);
	~Transaction(){delete t;}
	
	int length;
	int *t;
};

class Data
{
 public:
	
	Data(char *filename);
	~Data();
	
	Transaction *getNext();

 private:
	
	FILE *in;
	char *fn;
};

//*********************************item.h***************************************
class Item
{
 public:

  Item(unsigned i, unsigned s = 0) : id(i), support(s) {}

  bool operator< (const Item &i) const {return support < i.support;}

  mutable vector<unsigned> transactions;
  unsigned id;
  unsigned support;
};
Transaction::Transaction(const Transaction &tr)
{
  length = tr.length;
  t = new int[tr.length];
  for(int i=0; i< length; i++) 
    t[i] = tr.t[i];
}

Data::Data(char *filename)
{
  fn = filename;
  in = fopen(fn,"rt");
}

Data::~Data()
{
  if(in) fclose(in);
}


Transaction *Data::getNext()
{
  vector<int> list;
  char c;

  // read list of items
  do {
    int item=0, pos=0;
    c = getc(in);
    while((c >= '0') && (c <= '9')) {
      item *=10;
      item += int(c)-int('0');
      c = getc(in);
      pos++;
    }
    if(pos) list.push_back(item);
  }while(c != '\n' && !feof(in));
  
  if(feof(in)) return 0;
  // Note, also last transaction must end with newline, 
  // else, it will be ignored
  
  // put items in Transaction structure
  Transaction *t = new Transaction(list.size());
  for(int i=0; i<int(list.size()); i++)
    t->t[i] = list[i];

  return t;
}


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
	Data *dt1 = new Data("./small_data.txt");

	unsigned tnr = 0;
	set<Item> root;
  	multiset<Item> *allitems = new multiset<Item>;  
  	set<Item>::iterator it;
	
  	// read all transactions
  	while(Transaction *t = data->getNext()) {
    	for(int i=0; i<t->length;i++) {
      		it = root.find(Item(t->t[i],t->t[i]));
      		if(it == root.end()) 
      			it = root.insert(Item(t->t[i],t->t[i])).first;
      		it->transactions.push_back(tnr);
    	}
    	tnr++;
    	delete t;
  	}
  	for (int i = 0; i < it->transactions.size(); ++i)
  	{
  		cout << transactions[i] << " ";
  	}
  	cout << endl;
	

	return 0;
}