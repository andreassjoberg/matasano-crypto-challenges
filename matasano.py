#!/usr/bin/python
import base64
import binascii


# CONSTANTS
WORDLISTFILE = r'OSPD4.txt'
SET1CH4INPUTFILE = r'4.txt'
SET1CH6INPUTFILE = r'6.txt'


# Functions
def hextobase64(hexstring):
	bin = binascii.unhexlify(hexstring)
	return base64.b64encode(bin).decode()

def xor(binary1, binary2):
	return ''.join(chr(ord(a) ^ ord(b)) for a, b in zip(binary1, binary2))

def xor_key(data, key):
	l = len(key)
	buff = []
	for idx, val in enumerate(data):
		buff.append(chr(ord(val) ^ ord(key[idx % l])))
	return ''.join(buff)

def readwordlist(filepath):
	words = []
	f = open(filepath, 'r')
	for line in f:
		words.append(str.split(line, ' ')[0].lower())
	if f:
		f.close()
	return words

def scoresentence(sentence, words):
	score = 0
	for word in sentence.split(' '):
		for w in words:
			if w.lower() == word.lower():
				score += 1
				break
	return score

def findsinglebytexorcipher(hexstring, words):
	highscore = {}
	for i in range(ord('A'), ord('Z') + 1):
		result = ''
		for j in range(0, len(hexstring), 2):
			result += xor_key(binascii.unhexlify(hexstring[j:j+2]), chr(i))
		score = scoresentence(result, words)
		highscore[i] = (score, result, chr(i))
	result = []
	for score in highscore.items():
		if score[1][0] > 0:
			result.append(score)
	return result

def detectsinglecharacterxor(words):
	result = []
	f = open(SET1CH4INPUTFILE, 'r')
	i = 1
	for line in f:
		print i ,
		i += 1
		r = findsinglebytexorcipher(line.replace('\n', ''), words)
		if len(r) > 0:
			result.append(r)
			for res in r:
				print 'FOUND!'
				print 'Key: %s' % res[1][2]
				print 'Result: %s' % res[1][1]
	if f:
		f.close()
	return result

def hammingdistance(str1, str2):
	assert len(str1) == len(str2)
	return sum(ch1 != ch2 for ch1, ch2 in zip(bin(int(binascii.hexlify(str1), 16)), bin(int(binascii.hexlify(str2), 16))))

def b64filetobinary(filepath):
	f = open(SET1CH6INPUTFILE, 'r')
	l = ''
	for line in f:
		l += line.replace('\n', '')
	if f:
		f.close()
	return base64.b64decode(l)

def tryguesskeysize(data):
	for keysize in range(2, 40):
		#while len(data) > index + keysize * 2:
		distance = 0
		for index in range(0, keysize * 4, keysize):
			distance += hammingdistance(data[index:index+keysize], data[index+keysize:index+keysize*2])
		print 'Key: %d, distance: %d' % (keysize, distance / keysize)

def breakrepeatingkeyxor(data, keysize):
	

# Main
if __name__ == '__main__':
	print '''
	Set 1: Challange 1:
	Convert hex to base 64
	'''
	inputset1ch1 = r'49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
	expectedresultset1ch1 = r'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
	assert expectedresultset1ch1 == hextobase64(inputset1ch1)
	print 'Result: OK'

	print '''
	Set 1: Challange 2:
	Fixed XOR
	'''
	input1set1ch2 = r'1c0111001f010100061a024b53535009181c'
	input2set1ch2 = r'686974207468652062756c6c277320657965'
	expectedresultset1ch2 = r'746865206b696420646f6e277420706c6179'
	assert expectedresultset1ch2 == binascii.hexlify(xor(binascii.unhexlify(input1set1ch2), binascii.unhexlify(input2set1ch2)))
	print 'Result: OK'

	print '''
	Set 1: Challange 3:
	Single-byte XOR cipher
	'''
	words = readwordlist(WORDLISTFILE)
	#inputset1ch3 = r'1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
	#for res in findsinglebytexorcipher(inputset1ch3, words):
	#	print 'Key: %s' % res[1][2]
	#	print 'Result: %s' % res[1][1]


	print '''
	Set 1: Challange 4:
	Detect single-character XOR
	'''
	#for res in detectsinglecharacterxor(words):
	#	print 'Key: %s' % res[1][2]
	#	print 'Result: %s' % res[1][1]


	print '''
	Set 1: Challange 5:
	Implement repeating-key XOR
	'''
	input1set1ch5 = r'''Burning 'em, if you ain't quick and nimble I go crazy when I hear a cymbal'''
	input2set1ch5 = r'ICE'
	expectedresultset1ch5 = r'0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f'
	#print binascii.hexlify(xor_key(input1set1ch5, input2set1ch5))
	#print expectedresultset1ch5

	print '''
	Set 1: Challange 6:
	Break repeating-key XOR
	'''
	input1set1ch6 = r'this is a test'
	input2set1ch6 = r'wokka wokka!!!'
	assert 37 == hammingdistance(input1set1ch6, input2set1ch6)
	data = b64filetobinary(SET1CH6INPUTFILE)
	#tryguesskeysize(data)
	#breakrepeatingkeyxor(data, 3)
	breakrepeatingkeyxor(data, 5)
	#breakrepeatingkeyxor(data, 8)