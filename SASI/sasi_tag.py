#!/usr/bin/env python
# coding: utf-8

# In[2]:


import requests
import random
import json


class SASI(object):
    """docstring for SLAP"""
    def __init__(self, Ids_new=None, Ids_old=None, ID=None, k1_new=None, k2_new=None, k1_old=None, k2_old=None):
        self.Ids_new = Ids_new
        self.Ids_old = Ids_old
        self.ID = ID
        self.k1_new = k1_new
        self.k1_old = k1_old
        self.k2_new = k2_new
        self.k2_old = k2_old
    

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
    def stringXOR(self, a, b):
        result = ""
        for i in range(len(a)):
            if a[i] == b[i]:
                result += "0"
            else:
                result += "1"

        return result


    def stringOR(self, a, b):
        result = ""
        for i in range(len(a)):
            if (a[i] == '0' and b[i] == '0'):
                result += "0"
            else:
                result += "1"

        return result
    def reverse(self, str):
        s = ""
        for ch in str:
            s = ch + s
        return s
    def stringAddition(self, a, b):
        result = ""
        c = '0';
        r = self.reverse(a)
        s = self.reverse(b)
        for i in range(len(r)):
            if (r[i] == '1' and s[i] == '1'):
                if c=='1':
                    result += "1"
                else :
                    result += "0"
                c = '1'
            elif (r[i] == 0 and s[i] == 0):
                if c=='1':
                    result += "1"
                else:
                    result += "0"
                c = '0'
            else:
                if c=='1':
                    result += "0"
                    c = '1'
                else:
                    result += "1"
                    c = '0'
        result = self.reverse(result)            
        return result   
    def stringSub(self, a, b):
        result = ""
        c = '0';
        g = self.reverse(a)
        f = self.reverse(b)
        for i in range(len(g)):
            if f[i]=='1':
                if c=='1':
                    c = '1'
                    e = '0'
                    if g[i]=='1':
                        result += '1'
                    else:
                        result += '0'
                else:
                    e = '1'
                    if g[i]=='1':
                        result += '0'
                        c = '0'
                    else:
                        result += '1'
                        c = '1'
            else:
                if c=='1':
                    e = '1'
                    if g[i]=='1':
                        result += '0'
                        c = '0'
                    else:
                        result += '1'
                        c = '1'
                else:
                    e = '0'
                    c = '0'
                    if g[i] == '1':
                        result += '1'
                    else:
                        result += '0'
        result = self.reverse(result)
        return result
    def CurrentState(self):
        print("Ids_old = {}".format(self.Ids_old))
        print("k1_old = {}".format(self.k1_old))
        print("k2_old = {}".format(self.k2_old))
        print("Ids_new = {}".format(self.Ids_new))
        print("k1_new = {}".format(self.k1_new))
        print("k2_new = {}".format(self.k2_new))
    def UpdateKeys(self, n1, n2):
        self.k1_old = self.k1_new
        self.k2_old = self.k2_new
        self.Ids_old = self.Ids_new
        self.k1_new = self.stringXOR(self.k1_old, n2)
        self.k1_new = self.rotate(self.k1_new,self.HammingWeight(self.k1_old))
        self.k2_new = self.stringXOR(self.k2_old, n1)
        self.k2_new = self.rotate(self.k2_new,self.HammingWeight(self.k2_old))
        a = self.stringAddition(self.Ids_old,self.ID)
        b = self.stringXOR(n2 , self.k1_new)
        self.Ids_new = self.stringXOR(a, b)
        
class Tag(SASI):
    """docstring for Tag"""
    def ComputeChallenge(self, A, B, C):
        alpha = self.stringXOR(self.Ids_new, self.k1_new)
        N1 = self.stringXOR(A, alpha)
        beta = self.stringOR(self.Ids_new, self.k2_new)
        N2 = self.stringSub(B, beta)
        a = self.stringXOR(self.k1_new, N2)
        k1_update = self.rotate(a,self.HammingWeight(self.k1_new))
        b = self.stringXOR(self.k2_new, N1)
        k2_update = self.rotate(b,self.HammingWeight(self.k2_new))
        c = self.stringXOR(self.k1_new, k2_update)
        d = self.stringXOR(k1_update, self.k2_new)
        C1 = self.stringAddition(c,d)
        if C1 == C:
            print("So far so good")
            d = self.stringXOR(k2_update, self.ID)
            e = self.stringXOR(self.k1_new , self.k2_new)
            g = self.stringAddition(e , k1_update)
            D = self.stringXOR(g, d)
            self.UpdateKeys(N1, N2)
            return D        


# In[3]:


Ids_new = '1010000110011001'
#Id_new = 1001101111011001
ID = '0111001110010100'
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
	tag = Tag(Ids_new=Ids_new, k1_new=k1_new, k2_new=k2_new, ID=ID)
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




