#include <stdio.h>
#include <vector>
#include <set>
#include <iostream>
#include <algorithm>

using namespace std;

//******************************data.h********************************

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

//********************************eclat.h****************************
class Eclat
{
public:
	
	Eclat();
	~Eclat();
	
	void setData(char *file){data = new Data(file);}
	void setMinsup(unsigned ms){minsup = ms;}
	void setOutput(char *of){out = fopen(of, "wt");}
	
	double mine();
		
protected:
	
	double grow(multiset<Item> *items, unsigned supp, int *itemset, int depth, int *comb, int cl);
	void print(int *itemset, int il, int *comb, int cl, int support, int spos = 0, int depth = 0, int *current = 0);	

	unsigned minsup;
	Data *data;	
	FILE *out;
};



//*************************************data.cpp******************************

Transaction::Transaction(const Transaction &tr)
{
  length = tr.length;
  t = new int[tr.length];
  for(int i=0; i< length; i++) t[i] = tr.t[i];
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

//********************************eclat.cpp*************************
Eclat::Eclat() : data(0), out(0) {}

Eclat::~Eclat() 
{
  if(data) delete data;
  if(out) fclose(out);
}

double Eclat::mine() 
{
  unsigned tnr = 0;
  set<Item> root;
  multiset<Item> *allitems = new multiset<Item>;  
  set<Item>::iterator it;
	
  // read all transactions
  while(Transaction *t = data->getNext()) {
    for(int i=0; i<t->length;i++) {
      it = root.find(Item(t->t[i],t->t[i]));
      if(it == root.end()) it = root.insert(Item(t->t[i],t->t[i])).first;
      it->transactions.push_back(tnr);
    }
    tnr++;
    delete t;
  }

  // remove infrequent items and put items in support ascending order
  while((it = root.begin()) != root.end()) {
    if(it->transactions.size() >= minsup) {
      Item item(it->id, it->transactions.size());
      item.transactions = it->transactions;
      allitems->insert(item);
    }
    root.erase(it);
  }
  if(out) fprintf(out,"(%d)\n",tnr);

  // finding all itemsets
  int *itemset = new int[allitems->size()];
  int *comb = new int[allitems->size()];
  double added = grow(allitems, tnr, itemset, 1, comb, 0);
  delete [] comb;
  delete [] itemset;
  delete allitems;

  return added+1;
}

double Eclat::grow(multiset<Item> *items, unsigned supp, int *itemset, int depth, int *comb, int cl)
{
  double added = 0;
  const int sw = 2;
  
  while(!items->empty()) {
    int factor = 1, cbl = cl;
    multiset<Item> *children = new multiset<Item>;    
    multiset<Item>::iterator it2, it = items->begin();
    itemset[depth-1] = it->id;

    for(it2 = it, it2++; it2 != items->end(); it2++) {
      Item item(it2->id);
      insert_iterator< vector<unsigned> > res_ins(item.transactions, item.transactions.begin());
      
      if(depth < sw) { // make tidlists
	set_intersection(it->transactions.begin(), it->transactions.end(), it2->transactions.begin(), it2->transactions.end(), res_ins);
	item.support = item.transactions.size();
      } else { // make diffsets
	if(depth == sw) set_difference(it->transactions.begin(), it->transactions.end(), it2->transactions.begin(), it2->transactions.end(), res_ins);
	else set_difference(it2->transactions.begin(), it2->transactions.end(), it->transactions.begin(), it->transactions.end(), res_ins);
	item.support = it->support - item.transactions.size();
      }

      if(item.support == it->support) {
	factor *= 2;
        comb[cbl++] = item.id;
      } else if(item.support >= minsup) children->insert(item); 
    }
    print(itemset, depth, comb, cbl, it->support);
    added += factor + (factor * grow(children, it->support, itemset, depth+1, comb, cbl)); 
    delete children;
    items->erase(it);
  }

  return added;
}

void Eclat::print(int *itemset, int il, int *comb, int cl, int support, int spos, int depth, int *current)
{
  if(current==0) {
    if(out) {
      set<int> outset;
      for(int j=0; j<il; j++) outset.insert(itemset[j]); 
      for(set<int>::iterator k=outset.begin(); k!=outset.end(); k++) fprintf(out, "%d ", *k);
      fprintf(out, "(%d)\n", support);
      if(cl) {
        current = new int[cl];
        print(itemset,il,comb,cl,support,0,1,current);
        delete [] current;
      }
    }
  }
  else {
    int loper = spos;
    spos = cl;
    while(--spos >= loper) {
      set<int> outset;
      current[depth-1] = comb[spos];
      for(int i=0; i<depth; i++) outset.insert(current[i]);
      for(int j=0; j<il; j++) outset.insert(itemset[j]);
      for(set<int>::iterator k=outset.begin(); k!=outset.end(); k++) fprintf(out, "%d ", *k);
      fprintf(out, "(%d)\n", support);
      print(itemset, il, comb, cl, support, spos+1, depth+1, current);
    }
  }
}



//***************main function**************************
int main(int argc, char *argv[])
{
  if(argc < 3) {
    cerr << "usage: " << argv[0] << " datafile minsup [output]" << endl;
    return 1;
  }
  else {
    Eclat eclat;
    
    eclat.setData(argv[1]);
    eclat.setMinsup(atoi(argv[2]));
    if(argc==4) eclat.setOutput(argv[3]);
    
    cout << eclat.mine() << endl;
    return 0;
  }
}