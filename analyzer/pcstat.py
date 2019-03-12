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

# represents the PCStat itself.
class PCStat:
	# initialization of PCStat.
	def __init__(self):
		print "PCStat - initialization started"

		self.file_dict = dict()
		self.pc_dict = dict()
		self.binary_name = sys.argv[1]

		# read log file
		self.log_file = open(sys.argv[1], "r")

		# get the base address of given binary ELF
		self.base_address = self.get_base_address()

		# get the symbol table from binary ELF
		self.symbol_table = dict()
		self.code_finish_address = 0
		self.setup_symbol_table()


	# get base address from file
	def get_base_address(self):
		f = open(sys.argv[2], "r")
		return int(f.readline().split()[2], 16)


	# setup symbol table
	def setup_symbol_table(self):
		f = open(sys.argv[3], "r")

		# skip line before table starts
		line = f.readline()
		while line != "SYMBOL TABLE:\n":
			line = f.readline()
		

		# read each table, get address of .text
		while True:
			line = f.readline()
			if not line:
				break

			symbol = line.split()
			if len(symbol) < 6:
				break

			# check if the symbol is code
			if symbol[3] != ".text":
				if symbol[3] == ".fini":
					self.code_finish_address = int(symbol[0], 16)
					print "CODE FINISH ADDRESS: %x" % self.code_finish_address
				continue

			# store to symbol table: offset - function name
			symbol_name = symbol[5]
			for i in range(6, len(symbol)):
				symbol_name += " " + symbol[i]
			self.symbol_table[int(symbol[0], 16)] = symbol_name

	
	# read a line from log file
	def readline(self):
		return self.log_file.readline()


	# close log file
	def file_close(self):
		self.log_file.close()


	# get the symbols from given pcs.
	def convert_pc_to_symbol(self, pcs):
		ret = list()
		keys = self.symbol_table.keys()
		keys.sort()

		# convert every pc in pcs.
		for pc in pcs:
			# add base address to match the binary's address.
			pc += self.base_address

			func_name = ''
			for idx in range(len(keys) - 1):
				if keys[idx + 1] > pc:
					func_name = self.symbol_table[keys[idx]]
					break
				elif keys[idx + 1] == pc:
					print "FUNCTION POINTER DETECTED for PC 0x%x" % (pc)
					break

			if func_name == '':
				if self.code_finish_address > pc:
					func_name = self.symbol_table[keys[len(keys) - 1]]
				#else:
					#print "NO FUNCTION DETECTED for PC 0x%x" % (pc)
			else:
				ret.append(func_name)

		return ret



# represents each system call.
class Syscall:
	# args: array of string
	def __init__(self, args, pcstat):
		self.timestamp = int(args[0])
		self.latency = int(args[1])
		self.filename = args[2]
		self.pos = int(args[3])
		self.size = int(args[4])
		pcs = map(lambda x: int(x, 16), args[5].split())
		self.pcs = pcstat.convert_pc_to_symbol(pcs)

	
	# prints the system call information to file.
	def print_syscall(self, f):
		string = str(self.timestamp)
		string += "\t" + str(self.latency)
		string += "\t" + self.filename
		string += "\t" + str(self.pos)
		string += "\t" + str(self.size) + "\n"
		string += "Program Contexts : \n"
		for pc in self.pcs:
			string += "\t\t" + pc + "\n"
		f.write(string + "\n")



# temporary function for storing PC.
def pcs_into_string(pcs):
	ret = ''
	for pc in pcs:
		ret += pc
	return ret



# main function.
def main():
	pcstat = PCStat()
	logs = dict()

	while True:
		line = pcstat.readline()
		if not line:
			break

		syscall = Syscall(line.split("\t"), pcstat);

		# add syscall information to file_dict
		syscall_list = list()
		if syscall.filename in pcstat.file_dict:
			syscall_list = pcstat.file_dict[syscall.filename]
		syscall_list.append(syscall)
		pcstat.file_dict[syscall.filename] = syscall_list

		# add syscall information to pc_dict
		syscall_list = list()
		pcs_string = pcs_into_string(syscall.pcs)
		if pcs_string in pcstat.pc_dict:
			syscall_list = pcstat.pc_dict[pcs_string]
		syscall_list.append(syscall)
		pcstat.pc_dict[pcs_string] = syscall_list

		# write converted system call information to new file.
		f = open("logs/log_" + syscall.filename.split("/")[-1], "a")
		syscall.print_syscall(f)

	pcstat.file_close()

	# analyze given syscalls

main()
