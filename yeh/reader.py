from flask import Flask
import json
from flask import request
import random
from flask import jsonify

w='win'
l='lose'
app = Flask(__name__)
print("__name__ is ", __name__)

class YEH(object):
    """docstring for Yeh protocol"""
    def __init__(self, Id_new=None, Id_old=None, k_new=None, k_old=None):
        self.Id_new = Id_new
        self.Id_old = Id_old
        self.k_new = k_new
        self.k_old = k_old
    
    #Helper functions
    def stringXOR(self, a, b):
        result = ""
        for i in range(len(a)):
            if a[i] == b[i]:
                result += "0"
            else:
                result += "1"

        return result
    
    def stringOR(self, a, b):   #considering 'v' is 'or' operator.
            result = ""
            for i in range(len(a)):
                if a[i] == '1' or b[i]== '1':
                    result += "1"
                else:
                    result += "0"

            return result

    def stringAND(self, a, b):   #considering '+' is 'and' operator.
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

class Reader(YEH):
    """docstring for Reader"""
    #To compute challenge for Tag to authenticate it!
    def ComputeChallenge(self, n1, n2, Id_t):
        if Id_t==self.Id_new:
            f='0'
        else:
            f='1'
        A=self.stringXOR(self.stringXOR(self.Id_new,self.k_new),n1)
        B=self.stringXOR(self.stringOR(self.Id_new,self.k_new),n2)
        global ks
        ks=self.rotate(self.stringXOR(self.k_new,n2),n1)
        C=self.stringAND(self.stringXOR(ks,n1),n2)
        self.A=A
        self.B=B
        self.C=C
        self.f=f
        self.ks=ks
        self.n1 = n1
        self.n2 = n2
        return A,B,C,f

    #To solve challenge message as sent by tag!    
    def VerifyChallenge(self, D):
            kss=self.rotate(self.stringOR(self.k_new,self.n1),self.n2)
            calc_d=self.stringAND(self.stringXOR(kss,self.n2),self.n1)

            if calc_d== D:
                self.UpdateKeys(self.ks,kss,self.n1,self.n2)
                return w

    
Id_new = '0'
Id_old = '0'
Id_temp = Id_new   #will be used to set flag(either 0 or 1) value upon receiving IDS from tag!
k_new = '1101011111011000'
ks=''
n1 = bin(random.randint(2**15, 2**16))[2:]
n2 = bin(random.randint(2**15, 2**16))[2:]

@app.route('/ID', methods=['GET', 'POST']) 
def ID():
    if request.method == "POST":
        global Id_new
        Id_new = request.form.get('Id_new')    #id as send by tag
        # print(Id_new)
        ret = {'Id_new': Id_new}
    return ret
    
@app.route('/values', methods=['GET']) 
def values():
        # print(Id_new)
        # global Id_new
        global reader
        reader = Reader(Id_new=Id_new, k_new=k_new)
        A, B, C, f = reader.ComputeChallenge(n1,n2,Id_temp)
        val = {'A' : A ,'B' : B, 'C' : C, 'f' : f}
        return val    
    

@app.route('/verify', methods=['GET', 'POST']) 
# To verify challenge message sent by tag
def verification():
        if request.method == "POST":
            global D
            D = request.form.get('D')
            v=reader.VerifyChallenge(D)
            if(v=='win'):
                ret = {'state':"we win!!! Wohooo"}
                reader.CurrentState()
                return ret




if __name__ == '__main__':
    app.run(host='localhost', port="5000")