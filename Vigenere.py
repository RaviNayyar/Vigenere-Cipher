#!/usr/bin/python3

'''
	Author: Ravi Nayyar
	Date: 8/18/2020

'''
import sys
import os
from os import path

symbols = ["A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", 
 		   "S", "T", "U", "V", "W", "X", "Y", "Z", "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", 
 		   "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z", "1", "2", 
 		   "3", "4", "5", "6", "7", "8", "9", "0", "*", "+", ",", "-", ".", "/", ":", ";", "<", "=",
 		   ">", "?", "@", "[", "]", "^", "_", "`", "{", "|", "}", "~", " ", "!", "#", "$", "%", "&", 
 		   "'", "(", ")", "\"","\n",]
 

def print_example_usage():
	print("Example Usage: ./<program_name> <file_name> <0 (encrypt) or 1 (decrypt)>")


'''
	Name: vigenere_table_lookup
	Inputs:
		elem1: character that needs to be either encrypted or decrypted
		elem2: current OTP character
		operator: either 0 (for encryption) or 1 (for decryption)
	Outputs:
		The encrypted character if operator was 0 or
		the decrypted character if the operator was 1
'''
def vigenere_table_lookup(elem1, elem2, operator):
	try:
		elem1_index = symbols.index(elem1)
	except:	
		print("{} not found".format(elem1))
		exit(0)
	try:
		elem2_index = symbols.index(elem2)
	except:
		print("{} not found".format(elem1))
		exit(0)
	
	new_char = -1
	if operator == 0:
		new_char = (elem1_index + elem2_index)
		if new_char >= len(symbols):
			new_char = new_char - len(symbols)
	
	if operator == 1:
		new_char = (elem1_index - elem2_index)
		if new_char < 0:
			new_char = len(symbols) + new_char
	
	return symbols[new_char]


'''
	Name: set_otp_counter
	Inputs:
		counter: the current character index inside the OTP
		otp: the OTP
	Outputs:
		the index of the next character in the OTP
'''
def set_otp_counter(counter, otp):
	counter = counter + 1
	if counter == len(otp):
		counter = 0
	return counter

'''
	Name: encrypt_file
	Inputs:
		file_name: the full path of the file whose contents will be encrypted
		otp: the OTP
	Outputs:
		N/A
'''
def encrypt_file(file_name, otp):
	print("Encrypting {}".format(file_name))
	index = 0
	orig_file = open(file_name, 'r')
	os.system("touch encrypt_file.txt && rm encrypt_file.txt")
	encrypt_file = open("encrypt_file.txt", 'a')

	#Read each character in every line in the file and encrypt 
	#the character using the vigenere lookup table
	lines = orig_file.readlines()
	for line in lines:
		for char in line:
			enc_char = vigenere_table_lookup(char, otp[index], 0)
			encrypt_file.write(enc_char)
			index = set_otp_counter(index, otp)

	encrypt_file.close()
	
'''
	Name: decrypt_file
	Inputs:
		file_name: the full path of the file whose contents will be decrypted
		otp: the OTP
	Outputs:
		N/A
'''
def decrypt_file(file_name, otp):
	print("Decrypting {}".format(file_name))
	index = 0
	orig_file = open(file_name, 'r')
	os.system("touch decrypt_file.txt && rm decrypt_file.txt")
	decrypt_file = open("decrypt_file.txt", 'a')
	
	#Read each character in every line in the file and decrypt 
	#the character using the vigenere lookup table
	lines = orig_file.readlines()
	for line in lines:
		for char in line:
			decrypt_file.write(vigenere_table_lookup(char, otp[index], 1))
			index = set_otp_counter(index, otp)
	decrypt_file.close()
	

if __name__ == "__main__":
	
	#Check if valid arguments were given
	if (len(sys.argv) != 3):
		print_example_usage()
		exit(0)

	file_name = sys.argv[1]
	operation = sys.argv[2]

	f_exist = path.exists(file_name)
	if not f_exist:
		print("{} does not exist".format(file_name))
		exit(0)

	try:
		crypt = int(operation)
	except:
		print("Entered operation is not valid")
		print_example_usage()
		exit(0)


	otp = input("Enter one time password: ")
	
	#Encrypting or Decrypting the given file
	if crypt == 0:
		encrypt_file(file_name, otp)
		replace = input("Do you want to replace orignal file with the encrypted file? ")
		if replace.lower() == "yes" or replace.lower() == 'y':
			cmd = "mv encrypt_file.txt " + file_name
			os.system(cmd)
	elif crypt == 1:
		decrypt_file(file_name, otp)
		replace = input("Do you want to replace orignal file with the decrypted file? ")
		if replace.lower() == "yes" or replace.lower() == 'y':
			cmd = "mv decrypt_file.txt " + file_name
			os.system(cmd)
	else:
		print_example_usage()