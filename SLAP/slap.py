class SLAP(object):
	"""docstring for SLAP"""
	def __init__(self, Id_new=None, Id_old=None, k1_new=None, k2_new=None, k1_old=None, k2_old=None, threshold=None):
		self.Id_new = Id_new
		self.Id_old = Id_old
		self.k1_new = k1_new
		self.k1_old = k1_old
		self.k2_new = k2_new
		self.k2_old = k2_old
		self.threshold = threshold


	def HammingWeight(self, x):
		return x.count("1")

	def HammingWeightOptimized(self, x):
	    x -= (x >> 1) & 0x5555555555555555
	    x = (x & 0x3333333333333333) + ((x >> 2) & 0x3333333333333333)
	    x = (x + (x >> 4)) & 0x0f0f0f0f0f0f0f0f
	    return ((x * 0x0101010101010101) & 0xffffffffffffffff ) >> 56

	def GroupingRoutine(self, target, a, begin, length, threshold):
		if (length-begin) <= threshold:
			if begin not in target:
				target.append(begin)

			if length not in target:
				target.append(length)
			return
		w = self.HammingWeight(a[begin:length])
		self.GroupingRoutine(target, a, begin, length-w, threshold)
		self.GroupingRoutine(target, a, length-w, length, threshold)

						

	def split(self, target, a):
		split_ret = []
		for i in range(len(target)-1):
			split_ret.append(a[target[i]: target[i+1]])
		return split_ret

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

		return temp

	def stringXOR(self, a, b):
		result = ""
		for i in range(len(a)):
			if a[i] == b[i]:
				result += "0"
			else:
				result += "1"

		return result


	def Grouping(self, a, t):
		target = []
		self.GroupingRoutine(target, a, 0, len(a), t)
		return target

	def UpdateKeys(self, B, n, Blr, Clr):
		self.k1_old = self.k1_new
		self.k2_old = self.k2_new
		self.Id_old = self.Id_new

		self.k1_new = self.stringXOR(self.Conv(self.k1_old, n, ), self.k2_old)
		self.k2_new = self.stringXOR(self.Conv(self.k2_old, B), self.k1_old)
		self.Id_new = self.Conv(self.Id_old, self.stringXOR(n, Blr+Clr))

	def CurrentState(self):
		print("Id_old = {}".format(self.Id_old))
		print("k1_old = {}".format(self.k1_old))
		print("k2_old = {}".format(self.k2_old))
		print("Id_new = {}".format(self.Id_new))
		print("k1_new = {}".format(self.k1_new))
		print("k2_new = {}".format(self.k2_new))
		


	def Conv(self, a, b, threshold=None):
		if threshold is None:
			threshold = self.threshold
		target_a = self.Grouping(a, threshold)
		target_b = self.Grouping(b,threshold)
		print(target_a)
		print(target_b)

		rearrange_a = self.split(target_b, a)
		rearrange_b = self.split(target_a, b)
		print(rearrange_a)
		print(rearrange_b)

		final_a = self.rotateALL(rearrange_a)
		final_b = self.rotateALL(rearrange_b)
		print(final_a)
		print(final_b)
		return self.stringXOR(final_a, final_b)
		# return bin(int(final_a, 2) ^ int(final_b, 2)) [2:]

class Reader(SLAP):
	"""docstring for Reader"""

	def ComputeChallenge(self, n):
		A = self.Conv(self.k1_new, self.k2_new, self.threshold)
		A = self.stringXOR(A, n)

		a = self.rotate(self.k1_new, self.HammingWeight(n))
		b = self.Conv(self.k2_new, self.stringXOR(self.k2_new, n), self.threshold)
		c = self.rotate(b, self.HammingWeight(self.k1_new))
		d = self.Conv(a, self.stringXOR(self.k1_new, self.k2_new), self.threshold)

		B = self.stringXOR(c, d)

		if self.HammingWeight(B) %2:
			B_send = B[len(B)//2:]
		else:
			B_send = B[:len(B)//2]

		self.A = A
		self.B = B
		self.Blr = B_send
		self.n = n

		return A, B_send

	def VerifyChallenge(self, Clr):
		a = self.Conv(self.B, self.k1_new, self.threshold)
		b = self.Conv(self.k1_new, self.stringXOR(self.k2_new, self.n), self.threshold)
		c = self.Conv(a, b, self.threshold)
		C = self.stringXOR(c, self.Id_new)

		if self.HammingWeight(C) % 2:
			C_recv = C[len(C)//2:]
		else:
			C_recv = C[:len(C)//2]

		if C_recv == Clr:
			print("We win")
			self.UpdateKeys(self.B, self.n, self.Blr, Clr)


class Tag(SLAP):
	"""docstring for Tag"""
	def ComputeChallenge(self, A, Blr):
		n = self.Conv(self.k1_new, self.k2_new, self.threshold)
		n = self.stringXOR(n, A)

		a = self.rotate(self.k1_new, self.HammingWeight(n))
		b = self.Conv(self.k2_new, self.stringXOR(self.k2_new, n), self.threshold)
		c = self.rotate(b, self.HammingWeight(self.k1_new))
		d = self.Conv(a, self.stringXOR(self.k1_new, self.k2_new), self.threshold)

		B = self.stringXOR(c, d)

		if self.HammingWeight(B) %2:
			B_recv = B[len(B)//2:]
		else:
			B_recv = B[:len(B)//2]

		if B_recv == Blr:
			print("So far so good")
			a = self.Conv(B, self.k1_new, self.threshold)
			b = self.Conv(self.k1_new, self.stringXOR(self.k2_new, n), self.threshold)
			c = self.Conv(a, b, self.threshold)
			C = self.stringXOR(c, self.Id_new)

			if self.HammingWeight(C) % 2:
				C_send = C[len(C)//2:]
			else:
				C_send = C[:len(C)//2]

			self.UpdateKeys(B, n, B_recv, C_send)

			return C_send

		



 


if __name__ == '__main__':
	import random
	# Reader sends hello
	# Tag sends Id_new

	# Reader side communication
	threshold = 6
	Id_new = bin(random.randint(2**15, 2**16))[2:]
	k1_new = bin(random.randint(2**15, 2**16))[2:]
	k2_new = bin(random.randint(2**15, 2**16))[2:]

	n = bin(random.randint(2**15, 2**16))[2:]

	reader = Reader(Id_new=Id_new, k1_new=k1_new, k2_new=k2_new, threshold=threshold)
	A, B_send = reader.ComputeChallenge(n)

	tag = Tag(Id_new=Id_new, k1_new=k1_new, k2_new=k2_new, threshold=threshold)
	C = tag.ComputeChallenge(A, B_send)

	reader.VerifyChallenge(C)

	reader.CurrentState()
	print()
	tag.CurrentState()

	# print(A, B)
	# A = bit(int(reader.Conv(k1_new, k2_new),2) ^ n)[2:]
	# A = reader.Conv(k1_new, k2_new, threshold)
	# A = reader.stringXOR(A, n)

	# # B = c ^ d
	# a = reader.rotate(k1_new, reader.HammingWeight(n))
	# b = reader.Conv(k2_new, reader.stringXOR(k2_new, n), threshold)
	# c = reader.rotate(b, reader.HammingWeight(k1_new))
	# d = reader.Conv(a, reader.stringXOR(k1_new, k2_new), threshold)

	# B = reader.stringXOR(c, d)

	# if reader.HammingWeight(B) %2:
	# 	B_send = B[len(B)//2:]
	# else:
	# 	B_send = B[:len(B)//2]

	# Reader sends Tag A, B_send
	
	# tag = SLAP(Id_new=Id_new, k1_new=k1_new, k2_new=k2_new, threshold=threshold)
	# # Tag on receiving these values calculates n
	# tag_n = tag.Conv(k1_new, k2_new, threshold)
	# tag_n = tag.stringXOR(tag_n, A)

	# a = tag.rotate(k1_new, tag.HammingWeight(n))
	# b = tag.Conv(k2_new, tag.stringXOR(k2_new, n), threshold)
	# c = tag.rotate(b, tag.HammingWeight(k1_new))
	# d = tag.Conv(a, tag.stringXOR(k1_new, k2_new), threshold)

	# tag_B = tag.stringXOR(c, d)

	# if tag.HammingWeight(tag_B) %2:
	# 	B_tag = tag_B[len(tag_B)//2:]
	# else:
	# 	B_tag = tag_B[:len(tag_B)//2]

	# if B_send == B_tag:
	# 	print("So far so good")
	# 	a = tag.Conv(tag_B, k1_new, threshold)
	# 	b = tag.Conv(k1_new, tag.stringXOR(k2_new, n), threshold)
	# 	c = tag.Conv(a, b, threshold)
	# 	C = tag.stringXOR(c, Id_new)

	# 	if tag.HammingWeight(C) % 2:
	# 		C_send = C[len(C)//2:]
	# 	else:
	# 		C_send = C[:len(C)//2]
	# 	# Send C_send

	# # Reader Side
	# a = reader.Conv(B, k1_new, threshold)
	# b = reader.Conv(k1_new, reader.stringXOR(k2_new, n), threshold)
	# c = reader.Conv(a, b, threshold)
	# reader_C = reader.stringXOR(c, Id_new)

	# if reader.HammingWeight(reader_C) % 2:
	# 	C_reader = reader_C[len(reader_C)//2:]
	# else:
	# 	C_reader = reader_C[:len(reader_C)//2]

	# if C_reader == C_send:
	# 	print("We win")
