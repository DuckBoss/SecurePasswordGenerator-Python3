from hashlib import sha512
from base64 import b64encode
from os import urandom
import datetime as dt
import sys


class PwdGen:
	hashDict = ('abcdefghijklmnopqrstuvwyz'
				'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
				'0123456789') #!@#$%^&*()-
	hashExtraChars = '!@#$%^&*()-_'
	maxSize = 100
	outSize = 0
	workFactor = 0
	masterKey = 'empty'

	def __init__(self):
		print("Password Generator Initialized...\n")

	def make(self):
		self.masterKey = b64encode(urandom(64)).decode('utf-8')

		while (True):
			self.workFactor = int(input("Enter the generation iteration factor: [Recommended: 500 - 500,000]"))
			if not self.workFactor:
				print("Invalid Iteration Entry - Try Again")
				continue
			if self.workFactor < 1:
				print("Iteration Entry Is Too Low - Try Again [Recommended: 500-500,000]")
				continue
			break

		while (True):
			self.outSize = int(input("Enter the generated password length: [5-50 Range]"))
			if not self.outSize:
				print("Invalid Password Size Entry - Try Again")
				continue
			if self.outSize < 5:
				print("Password Entry Is Too Low - Try Again [5-50 Range]")
				continue
			if self.outSize > 50:
				print("Password Entry Is Too High - Try Again [5-50 Range]")
				continue
			break

		while (True):
			useExtraChars = input("Use Special Characters? [Y/N]")
			if not useExtraChars:
				print("Invalid Entry - Try Again")
				continue
			if useExtraChars.capitalize() == 'Y':
				print("Implementing Special Characters...")
				self.hashDict += self.hashExtraChars;
				break
			elif useExtraChars.capitalize() == 'N':
				print("Ignoring Special Characters...")
				break
			else:
				print("Invalid Entry - Try Again")
				continue
			break

		finalPass = self.generatePassword()
		if not finalPass:
			print("Fatal Error - Generation Failed.")
			sys.exit(1)
		return finalPass

	def generatePassword(self):
		print("Given - {}".format(self.masterKey))

		self.masterKey = self.masterKey.replace(" ", "")
		self.masterKey = self.masterKey.strip()
		self.masterKey = self.masterKey.strip('\n')
		self.masterKey = self.masterKey.strip('\t')

		print("[0%]:Task - Hashing")
		hashedString = self.getSHA512(self.masterKey, b64encode(urandom(64)).decode('utf-8'))
		print("[1%]:Task - Hashing")
		for x in range(1, self.workFactor):
			hashedString = self.getSHA512(hashedString, b64encode(urandom(64)).decode('utf-8'))
			print("[{}%]:Task - {}".format((int)(((float)(x + 1) / self.workFactor) * 100), "Hashing..."))

		b74String = self.getBase74(hashedString, self.hashDict)
		return b74String

	def getSHA512(self, rawPassword, salt):
		return sha512((rawPassword + salt).encode("utf-8")).hexdigest()


	def getBase74(self, hashedPassword, base74Val):
		## Special thanks to coleifer for a custom hash dictionary with Base 74 implementation ##
		num = int(hashedPassword, 16)
		num_chars = len(base74Val)
		chars = []
		while len(chars) < self.outSize:
			num, idx = divmod(num, num_chars)
			chars.append(base74Val[idx])

		return ''.join(chars)


def main():
	startTime = dt.datetime.now()
	program = PwdGen()
	generatedPassword = program.make()
	print("Generated Password - {}".format(generatedPassword))
	endTime = dt.datetime.now()
	print("Total Time: {}".format(endTime - startTime))


if __name__ == "__main__":
	main()
