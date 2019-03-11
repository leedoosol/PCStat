# -*- coding:UTF-8 -*-
import os
import sys

'''
	Implementation of PCStat:
		analyze given log, which is in format:
			(timestamp, latency, filename, starting position, size, program contexts)
		analyze by program context and file to catch file I/O pattern and latency.
	
	sys.argv[1]: log file name
	sys.argv[2]: base address filename
	sys.argv[3]: symbol table filename
'''

class Syscall:
	# args: array of string
	def __init__(self, args):
		self.timestamp = int(args[0])
		self.latency = int(args[1])
		self.filename = args[2]
		self.pos = int(args[3])
		self.size = int(args[4])
		self.pcs = args[5].split(' ') # TODO remove function pointers

def pcs_into_string(pcs):
	ret = ''
	for pc in pcs:
		ret += pc
	return ret

def main():
	file_dict = dict()
	pc_dict = dict()
	
	# read log file
	f = open(sys.argv[1], "r")

	while True:
		line = f.readline()
		if not line:
			break

		syscall = Syscall(line.split("\t"));

		# add syscall information to file_dict
		syscall_list = list()
		if syscall.filename in file_dict:
			syscall_list = file_dict[syscall.filename]
		syscall_list.append(syscall)
		file_dict[syscall.filename] = syscall_list

		# add syscall information to pc_dict
		syscall_list = list()
		pcs_string = pcs_into_string(syscall.pcs)
		if pcs_string in pc_dict:
			syscall_list = pc_dict[pcs_string]
		syscall_list.append(syscall)
		pc_dict[pcs_string] = syscall_list

	f.close()

	# analyze given syscalls

main()
