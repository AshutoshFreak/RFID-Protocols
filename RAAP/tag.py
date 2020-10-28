import requests

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


class Tag(RAAP):
	"""docstring for Tag"""
	def InitialChallenge(self, Id_new):  
		return Id_new        
	def ComputeChallenge(self, A, B):
		n1 =  self.rec(self.k1_new, self.k2_new)
		n1 = self.stringXOR(n1, A)
		a = self.rotate(n1, self.HammingWeight(n1))
		b = self.rec(self.k2_new, n1)
		c = self.rec(self.k3_new, n1)        
		d = self.rotate(b, self.HammingWeight(c))
		B1 = self.stringXOR(a, d)
		if B1 == B:
			print("So far so good")
			a = self.rec(self.k2_new, self.k3_new)
			b = self.rec(n1, self.k3_new)
			c = self.rec(a, b)
			C = self.stringXOR(c, self.Id_new)
			return C


	def FinalChallenge(self, D, E):
		a = self.rotate(n1, self.HammingWeight(n1))
		b = self.rec(self.k2_new, n1)
		c = self.stringXOR(a, b) 
		n2 = self.stringXOR(c, D)
		x = self.rotate(n2, self.HammingWeight(n2))
		y = self.rec(self.k2_new, n2)
		z = self.rec(self.k2_new, n1)        
		d = self.rotate(y, self.HammingWeight(z))
		E1 = self.stringXOR(x, d)
		if E1 == E:
			print("Successful Authentication")
		self.UpdateKeys(n1, n2)


def connect(to_call, param):
    adr = f'http://localhost:8080/{to_call}/{param}'
    print(adr)
    r = requests.get(url=adr)
    return(r.json()['ct'])


if __name__ == "__main__":
	Id_new = '1010110110110101' # bin(random.randint(2**15, 2**16))[2:]
	k1_new = '1001101001111000' # bin(random.randint(2**15, 2**16))[2:]
	k2_new = '1001011100110111' # bin(random.randint(2**15, 2**16))[2:]
	k3_new = '1110011100110000' # bin(random.randint(2**15, 2**16))[2:]
	n1 = '1101111001101011' # bin(random.randint(2**15, 2**16))[2:]
	n2 = '1111111000001100' # bin(random.randint(2**15, 2**16))[2:]
	tag = Tag(Id_new=Id_new, k1_new=k1_new, k2_new=k2_new, k3_new=k3_new)
	Id_new =  tag.InitialChallenge(Id_new)

	# q = reader.InitialChallenge(Id_new)
	# A, B = reader.ComputeChallenge(n1)
	adr = f'http://localhost:8080/InitialChallenge/{Id_new}'
	r = requests.get(url=adr)
	A = r.json()['A']
	B = r.json()['B']

	C = tag.ComputeChallenge(A, B)

	# reader.VerifyChallenge(C)
	# D, E = reader.FinalChallenge(n2, n1)
	adr = f'http://localhost:8080/VerifyChallenge/{C}'
	r = requests.get(url=adr)
	D = r.json()['D']
	E = r.json()['E']

	tag.FinalChallenge(D, E)
	tag.CurrentState()
