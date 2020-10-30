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
            lis[i] = lis[self.seed(n1, n2, k)]
        lis[self.seed(n1, n2, k)] = self.rotateALL(lis[self.seed(n1, n2, k)])
        final_a = self.stringXOR(lis,lis1)
    def rh(self,a,k=None): 
        if k is None:
            k = self.k
        lis = [] 
        lis1 = []
        final_a = ' '
        lis = self.split_str(a,k)
        q = lis[self.seed(n1, n2, k)]
        ##lis1 = lis
        for i in range(0, len(lis)):
            if i!=q:
                s=lis[i]
                w=self.stringXOR(s,q)
                lis1.extend(w)
            elif i==q:
                s=self.rotateALL(lis[self.seed(n1, n2, k)])
                lis1.extend(s)
           ## lis[i] = lis[self.seed(n1, n2, k)]
       ## lis[self.seed(n1, n2, k)] = self.rotateALL(lis[self.seed(n1, n2, k)])
       ## final_a = final_a+self.stringXOR(lis,lis1) 
        ##print(lis1)
        lis2 = ''.join(map(str, lis1))
        ##print(lis2)
        return lis2
class Reader(RCIA):
    """docstring for Reader"""

    def ComputeChallenge(self):
        A = self.rotate(self.Ids_new, self.HammingWeight(self.k1_new)) 
        A = self.stringXOR(A, n1)

        a = self.stringXOR(self.Ids_new, n1)
        b = self.rotate(a, self.HammingWeight(self.k2_new))
        c = self.stringXOR(b, self.k1_new)
        B = self.stringXOR(c, n2)
        k4 = self.rotate(self.rh(self.k2_new,self.k), self.HammingWeight(self.rh(n1,self.k)))
        k4 = self.stringXOR(k4, self.k1_new)
        k5 = self.rotate(self.rh(self.k1_new,self.k), self.HammingWeight(self.rh(n2,self.k)))
        k5 = self.stringXOR(k5, self.k2_new)
        d = self.rotate(self.rh(k4,self.k),self.HammingWeight(self.rh(k5,self.k)))
        e = self.rotate(self.rh(n1,self.k), self.HammingWeight(self.rh(n2,self.k)))
        C = self.stringXOR(d, e)

        self.k4 = k4
        self.k5 = k5               
        self.A = A
        self.B = B
        self.C = C
        self.n1 = n1
        self.n2 = n2                
        return A, B, C
    def VerifyChallenge(self, D):
        a = self.rotate(self.rh(self.Ids_new,self.k), self.HammingWeight(self.k4))
        b = self.rotate(self.rh(self.k5,self.k), self.HammingWeight(self.rh(n2,self.k)))
        c = self.stringXOR(b, self.Ids_new)
        C = self.stringXOR(c, a)

        if C == D:
            print("We won")
            self.UpdateKeys(n1, n2)

class Tag(RCIA):
    """docstring for Tag"""
    def ComputeChallenge(self, A, B, C):
        n1 = self.rotate(self.Ids_new, self.HammingWeight(self.k1_new))
        n1 = self.stringXOR(n1, A)
        a = self.stringXOR(self.Ids_new, n1)
        b = self.rotate(a, self.HammingWeight(self.k2_new))
        c = self.stringXOR(b, self.k1_new)
        n2 = self.stringXOR(B, c)
        k4 = self.rotate(self.rh(self.k2_new,self.k), self.HammingWeight(self.rh(n1,self.k)))
        k4 = self.stringXOR(k4, self.k1_new)
        k5 = self.rotate(self.rh(self.k1_new,self.k), self.HammingWeight(self.rh(n2,self.k)))
        k5 = self.stringXOR(k5, self.k2_new)
        
        d = self.rotate(self.rh(k4,self.k),self.HammingWeight(self.rh(k5,self.k)))
        e = self.rotate(self.rh(n1,self.k), self.HammingWeight(self.rh(n2,self.k)))
        C1 = self.stringXOR(d, e)
        self.k4 = k4
        self.k5 = k5  
        self.n2 = n2
        ##print(k4)
        ##print(k5)
        if C1 == C:
            print("So far so good")
            a = self.rotate(self.rh(self.Ids_new,self.k), self.HammingWeight(self.k4))
            b = self.rotate(self.rh(self.k5,self.k), self.HammingWeight(self.rh(n2,self.k)))
           ## print(Ids_new)
            ##print(b)
            c = self.stringXOR(b, self.Ids_new)
           ## print(a)
           ## print(c)
            D = self.stringXOR(c, a)

            self.UpdateKeys(n1, n2)
        return D
           


# In[ ]:


if __name__ == '__main__':
    import random
    k = 4
    Ids_new = bin(random.randint(2**15, 2**16))[2:]
    k1_new = bin(random.randint(2**15, 2**16))[2:]
    k2_new = bin(random.randint(2**15, 2**16))[2:]
    n1 = bin(random.randint(2**15, 2**16))[2:]
    n2 = bin(random.randint(2**15, 2**16))[2:]
    
    ##reader = Reader(Ids_new=Ids_new, k1_new=k1_new, k2_new=k2_new, k=k)
    reader = Reader(Ids_new=Ids_new, k1_new=k1_new, k2_new=k2_new, k=k)
    A, B, C = reader.ComputeChallenge()

    tag = Tag(Ids_new=Ids_new, k1_new=k1_new, k2_new=k2_new, k=k)
    D = tag.ComputeChallenge(A, B, C)

    reader.VerifyChallenge(D)

    reader.CurrentState()
    print()
    tag.CurrentState()

