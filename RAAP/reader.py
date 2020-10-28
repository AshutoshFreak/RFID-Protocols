import flask
import json
import random

class RAAP(object):
	def __init__(self, Id_new=None, Id_old=None, k1_new=None, k2_new=None, k1_old=None, k2_old=None, k3_new=None, k3_old=None):
		self.Id_new = Id_new
		self.Id_old = Id_old
		self.k1_new = k1_new
		self.k1_old = k1_old
		self.k2_new = k2_new
		self.k2_old = k2_old
		self.k3_new = k3_new
		self.k3_old = k3_old


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


	def rec(self, a, b):
		result = ""
		for i in range(len(a)):
			if a[i] == b[i]:
				result += a[i]
			elif i == (len(a)-1):
				if a[i] > b[i]:
					result += a[0]
				if b[i] > a[i]:
					result += b[0]    
			elif a[i] > b[i]:
				result += a[i+1]
			elif a[i] < b[i]:
				result += b[i+1]
		return result


	def UpdateKeys(self, n1, n2):
		self.k1_old = self.k1_new
		self.k2_old = self.k2_new
		self.Id_old = self.Id_new
		self.k3_old = self.k3_new        
		self.k1_new = self.stringXOR(self.rec(self.stringXOR(self.k1_old, n2), n1), self.k2_old)
		self.k2_new = self.stringXOR(self.rec(self.k2_old, self.stringXOR(n2, n1)), self.k3_old)
		self.k3_new = self.stringXOR(self.rec(self.k2_old, self.k3_old), n1)        
		self.Id_new = self.stringXOR(self.rec(self.stringXOR(self.Id_old, n2), self.k3_old), self.k1_old)


	def CurrentState(self):
		print("Id_old = {}".format(self.Id_old))
		print("k1_old = {}".format(self.k1_old))
		print("k2_old = {}".format(self.k2_old))
		print("Id_new = {}".format(self.Id_new))
		print("k1_new = {}".format(self.k1_new))
		print("k3_new = {}".format(self.k2_new))
		print("k3_old = {}".format(self.k2_old))


class Reader(RAAP):
	"""docstring for Reader"""
	def InitialChallenge(self, Id_new):  
		q = Id_new        
		self.q = q
		return q        


	def ComputeChallenge(self, n1):
		A = self.rec(self.k1_new, self.k2_new) 
		A = self.stringXOR(A, n1)
		a = self.rotate(n1, self.HammingWeight(n1))
		b = self.rec(self.k2_new, n1)
		c = self.rec(self.k3_new, n1)        
		d = self.rotate(b, self.HammingWeight(c))
		B = self.stringXOR(a, d)
		self.A = A
		self.B = B
		self.n1 = n1
		return A, B


	def VerifyChallenge(self, C):
		a = self.rec(self.k2_new, self.k3_new)
		b = self.rec(self.n1, self.k3_new)
		c = self.rec(a, b)
		C1 = self.stringXOR(C, c)      
		if C1 == self.q:
			print("We are communicating with right tag")


	def FinalChallenge(self, n2, n1):
		a = self.rotate(n1, self.HammingWeight(n1))
		b = self.rec(self.k2_new, n1)
		c = self.stringXOR(a, b) 
		D = self.stringXOR(c, n2)
		x = self.rotate(n2, self.HammingWeight(n2))
		y = self.rec(self.k2_new, n2)
		z = self.rec(self.k2_new, n1)        
		d = self.rotate(y, self.HammingWeight(z))
		E = self.stringXOR(x, d)
		self.D = D
		self.E = E
		self.n2 = n2
		self.UpdateKeys(n1, n2)
		return D, E


@app.route('/InitialChallenge/<id_new>', methods=['GET'])
def InitialChallenge(id_new):
	global A, B
	reader.InitialChallenge(id_new)
	A, B = reader.ComputeChallenge(n1)
	return {'A': A, 'B': B}
	


adr = f'http://localhost:8080/VerifyChallenge/{C}'
def VerifyChallenge(C):
	reader.VerifyChallenge(C)
	D, E = reader.FinalChallenge(n2, n1)
	reader.CurrentState()
	return {'D': D, 'E': E}



# adr = f'http://localhost:8080/VerifyChallenge/{C}'
# def InitialChallenge



Id_new = '1010110110110101' # bin(random.randint(2**15, 2**16))[2:]
k1_new = '1001101001111000' # bin(random.randint(2**15, 2**16))[2:]
k2_new = '1001011100110111' # bin(random.randint(2**15, 2**16))[2:]
k3_new = '1110011100110000' # bin(random.randint(2**15, 2**16))[2:]
n1 = '1101111001101011' # bin(random.randint(2**15, 2**16))[2:]
n2 = '1111111000001100' # bin(random.randint(2**15, 2**16))[2:]
reader = Reader(Id_new=Id_new, k1_new=k1_new, k2_new=k2_new, k3_new=k3_new)
app = flask.Flask(__name__)
A = 0
B = 0