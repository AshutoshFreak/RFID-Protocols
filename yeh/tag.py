import requests
import random
import json

class YEH(object):
    """docstring for Yeh protocol"""
    def __init__(self, Id_new=None, Id_old=None, k_new=None, k_old=None):
        self.Id_new = Id_new
        self.Id_old = Id_old
        self.k_new = k_new
        self.k_old = k_old

    #helper functions-
    def stringXOR(self, a, b):
        result = ""
        for i in range(len(a)):
            if a[i] == b[i]:
                result += "0"
            else:
                result += "1"

        return result
    
    def stringOR(self, a, b):   #considering 'v' is or operator.
            result = ""
            for i in range(len(a)):
                if a[i] == '1' or b[i]== '1':
                    result += "1"
                else:
                    result += "0"

            return result

    def stringAND(self, a, b):   #considering '+' is and operator.
            result = ""
            for i in range(len(a)):
                if a[i] == '1' and b[i]== '1':
                    result += "1"
                else:
                    result += "0"

            return result
    
    def rotate(self, string1, string2):
        x = string2.count("1")
        if len(string1) == 0 or x < 0 or x > len(string1):
            return ""

        if x == 0:
            return string1

        s1 = string1[:x]
        s2 = string1[x:]
        return s2+s1


    def UpdateKeys(self, ks, kss, n1, n2):
        self.k_old = self.k_new
        self.Id_old = self.Id_new

        self.k_new = ks
        temp1=self.stringAND(self.Id_new,(self.stringXOR(self.Id_new,kss)))
        temp2=self.stringXOR(n1,n2)
        self.Id_new = self.stringXOR(temp1,temp2)

    def CurrentState(self):
        print("Id_old = {}".format(self.Id_old))
        print("k_old = {}".format(self.k_old))
        print("Id_new = {}".format(self.Id_new))
        print("k_new = {}".format(self.k_new))

class Tag(YEH):
    """docstring for Tag"""
    def ComputeChallenge(self, A, B, C, f): 
        n1=self.stringXOR(self.stringXOR(self.Id_new,self.k_new),A)
        n2=self.stringXOR(self.stringOR(self.Id_new,self.k_new),B)
        kstar=self.rotate(self.stringXOR(self.k_new,n2),n1)
        calc_c=self.stringAND(self.stringXOR(kstar,n1),n2)
        if calc_c==C:
            #print("Tag authentication is done successfully")
            #print("Let's generate challenge message for Reader!")
            ks=self.rotate(self.stringXOR(self.k_new,n2),n1)
            kss=self.rotate(self.stringOR(self.k_new,n1),n2)
            D=self.stringAND(self.stringXOR(kss,n2),n1)
            if f=='0':
                self.UpdateKeys(ks,kss,n1,n2)
            return D

Id_new = bin(random.randint(2**15, 2**16))[2:] #Treated as IDS new
k_new = '1101011111011000'

def sendID():
    adr = 'http://localhost:5000/ID'
    r = requests.post(url =adr, data={'Id_new': Id_new})
    if r.status_code != 200:
        print("Error:", r.status_code)

    data1 = r.json()
    
    return data1

# Reads the value i.e challenge message as sent by Reader
def values():    
    global data2
    adr = 'http://localhost:5000/values'
    r = requests.get(url =adr)
    try:
        response = r.text
        data2 = json.loads(response)
        return data2
    except json.JSONDecodeError as e:
        print("Response content is not valid JSON", e)

# To solve the challenge message sent by reader, as well as generate challenge message for Reader!
def verification():
    global A ,B ,C ,f, D, tag, data2
    A = list(data2.values())[0]
    B = list(data2.values())[1]
    C = list(data2.values())[2]
    f = list(data2.values())[3]
    tag = Tag(Id_new=Id_new, k_new=k_new)
    D = tag.ComputeChallenge(A, B, C, f)
    adr = 'http://localhost:5000/verify'
    r = requests.post(url =adr, data={'D': D})
    if r.status_code != 200:
        print("Error:", r.status_code)

    data3 = r.json()
    return data3

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