#!/usr/bin/env python
# coding: utf-8

# In[2]:


import requests
import random
import json



class RCIA(object):
    """docstring for SLAP"""
    def __init__(self, Ids_new=None, Ids_old=None, k1_new=None, k2_new=None, k1_old=None, k2_old=None, k=None):
        self.Ids_new = Ids_new
        self.Ids_old = Ids_old
        self.k1_new = k1_new
        self.k1_old = k1_old
        self.k2_new = k2_new
        self.k2_old = k2_old
        self.k = k
    

    def HammingWeight(self, x):
        return x.count("1")

    def rotate(self, string, hamming_weight):
        if len(string) == 0 or hamming_weight < 0 or hamming_weight > len(string):
            return ""
        if hamming_weight == 0:
            return string
        p1 = string[:hamming_weight]
        p2 = string[hamming_weight:]
        return p2+p1
       
    def rotateALL(self, list_substr):
            temp = ""
            for sub in list_substr:
                temp += self.rotate(sub, self.HammingWeight(sub))

    def stringXOR(self, a, b):
        result = ""
        for i in range(len(a)):
            if a[i] == b[i]:
                result += "0"
            else:
                result += "1"

        return result


    def stringAND(self, a, b):
        result = ""
        for i in range(len(a)):
            if a[i] == b[i]:
                result += "1"
            else:
                result += "0"

        return result

    def UpdateKeys(self, n1, n2):
        self.k1_old = self.k1_new
        self.k2_old = self.k2_new
        self.Ids_old = self.Ids_new
        self.k1_new = self.rotate(self.rh(self.k2_old,self.k), self.HammingWeight(self.rh(n1,self.k)))
        self.k1_new = self.stringXOR(self.k1_new, self.k1_old)
        self.k2_new = self.rotate(self.rh(self.k1_old,self.k), self.HammingWeight(self.rh(n2,self.k)))
        self.k2_new = self.stringXOR(self.k2_new, self.k2_old)
        self.Ids_new = self.stringXOR(self.rh(self.Ids_old,self.k),n2) 
        self.Ids_new = self.rotate(self.Ids_new, self.HammingWeight(n1))
    
    def seed(self, n1, n2, k):
        SEED = self.stringXOR(n1, n2)
        X = len(SEED) % k
        return X

    def CurrentState(self):
        print("Ids_old = {}".format(self.Ids_old))
        print("k1_old = {}".format(self.k1_old))
        print("k2_old = {}".format(self.k2_old))
        print("Ids_new = {}".format(self.Ids_new))
        print("k1_new = {}".format(self.k1_new))
        print("k2_new = {}".format(self.k2_new))

    def split_str(self, seq, chunk, skip_tail=False):
        lst = []
        if chunk <= len(seq):
            lst.extend([seq[:chunk]])
            lst.extend(self.split_str(seq[chunk:], chunk, skip_tail))
        elif not skip_tail and seq:
            lst.extend([seq])
        ##print(lst)   
        return lst

    def comp(self,a,k=None):
        if k is None:
            k = self.k
        lis = [] 
        lis1 = []
        lis = self.split_str(a,k)
        lis1 = lis
        for i in range(0, len(lis)-1):
            lis[i] = lis[self.seed(self.n1, self.n2, k)]
        lis[self.seed(self.n1, self.n2, k)] = self.rotateALL(lis[self.seed(self.n1, self.n2, k)])
        final_a = self.stringXOR(lis,lis1)
    def rh(self,a,k=None): 
        if k is None:
            k = self.k
        lis = [] 
        lis1 = []
        final_a = ' '
        lis = self.split_str(a,k)
        q = lis[self.seed(self.n1, self.n2, k)]
        ##lis1 = lis
        for i in range(0, len(lis)):
            if i!=q:
                s=lis[i]
                w=self.stringXOR(s,q)
                lis1.extend(w)
            elif i==q:
                s=self.rotateALL(lis[self.seed(self.n1, self.n2, k)])
                lis1.extend(s)
           ## lis[i] = lis[self.seed(n1, n2, k)]
       ## lis[self.seed(n1, n2, k)] = self.rotateALL(lis[self.seed(n1, n2, k)])
       ## final_a = final_a+self.stringXOR(lis,lis1) 
        ##print(lis1)
        lis2 = ''.join(map(str, lis1))
        ##print(lis2)
        return lis2
    
class Tag(RCIA):
    """docstring for Tag"""
    def ComputeChallenge(self, A, B, C):
        n1 = self.rotate(self.Ids_new, self.HammingWeight(self.k1_new))
        n1 = self.stringXOR(n1, A)
        a = self.stringXOR(self.Ids_new, n1)
        b = self.rotate(a, self.HammingWeight(self.k2_new))
        c = self.stringXOR(b, self.k1_new)
        n2 = self.stringXOR(B, c)
        self.n2 = n2
        self.n1 = n1
        k4 = self.rotate(self.rh(self.k2_new,self.k), self.HammingWeight(self.rh(self.n1,self.k)))
        k4 = self.stringXOR(k4, self.k1_new)
        k5 = self.rotate(self.rh(self.k1_new,self.k), self.HammingWeight(self.rh(self.n2,self.k)))
        k5 = self.stringXOR(k5, self.k2_new)
        
        d = self.rotate(self.rh(k4,self.k),self.HammingWeight(self.rh(k5,self.k)))
        e = self.rotate(self.rh(self.n1,self.k), self.HammingWeight(self.rh(self.n2,self.k)))
        C1 = self.stringXOR(d, e)
        self.k4 = k4
        self.k5 = k5  
        ##self.n2 = n2
        ##self.n1 = n1
        ##print(k4)
        ##print(k5)
        if C1 == C:
            print("So far so good")
            a = self.rotate(self.rh(self.Ids_new,self.k), self.HammingWeight(self.k4))
            b = self.rotate(self.rh(self.k5,self.k), self.HammingWeight(self.rh(self.n2,self.k)))
           ## print(Ids_new)
            ##print(b)
            c = self.stringXOR(b, self.Ids_new)
           ## print(a)
           ## print(c)
            D = self.stringXOR(c, a)

            self.UpdateKeys(self.n1, self.n2)
        return D
           
    


# In[3]:


Ids_new = bin(random.randint(2**15, 2**16))[2:]
#Id_new = 1001101111011001
k = 4
k1_new = '1101011111011000'
k2_new = '1101000010100100'


# In[4]:


def sendID():
	adr = 'http://localhost:5000/ID'
	r = requests.post(url =adr, data={'Ids_new': Ids_new})
	if r.status_code != 200:
  		print("Error:", r.status_code)

	data1 = r.json()
	return data1


# In[5]:


def values():	
	global data2
	adr = 'http://localhost:5000/values'
	r = requests.get(url =adr)
	try:
		response = r.text
		data2 = json .loads(response)
		return data2
	except json.JSONDecodeError as e:
		print("Response content is not valid JSON", e)


# In[6]:


def verification():
	global A ,B ,C ,D ,tag
	A = list(data2.values())[0]
	B = list(data2.values())[1]
	C = list(data2.values())[2]
	tag = Tag(Ids_new=Ids_new, k1_new=k1_new, k2_new=k2_new, k=k)
	D = tag.ComputeChallenge(A, B ,C)
	adr = 'http://localhost:5000/verify'
	r = requests.post(url =adr, data={'D': D})
	if r.status_code != 200:
  		print("Error:", r.status_code)

	data3 = r.json()
	return data3

 	


# In[7]:


if __name__ == '__main__':
	data1 = sendID()
	# print(data1)

	data2 = values()
	# print(data2)

	data3 = verification()
	state = list(data3.values())[0]
	print(state)
	print("Tag's current state :")
	tag.CurrentState()

	


# In[ ]:




