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

		# get the base address of binary
		self.base_address = self.get_base_address()
		print "BASE ADDRESS: %x" % self.base_address

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
				continue

			# check if the symbol is code
			if symbol[3] != ".text":
				if symbol[3] == ".fini":
					self.code_finish_address = int(symbol[0], 16)
					print "CODE FINISH ADDRESS: %x" % self.code_finish_address
				continue

			if symbol[5] != ".text":
				# store to symbol table: offset - function name
				symbol_name = symbol[5]
				for i in range(6, len(symbol)):
					symbol_name += " " + symbol[i]
				self.symbol_table[int(symbol[0], 16)] = symbol_name
		#check symtab
		print "############## symtbl check ###############"
		keys = self.symbol_table.keys()
		keys.sort()
		for PC in keys:
			print "0x%x - %s" % (PC, self.symbol_table[PC])
		print "############################################"

	
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
		for pc_offset in pcs:
			# add base address to match the binary's address.
			pc = pc_offset + self.base_address

			func_name = ''
			for idx in range(len(keys) - 1):
				if keys[idx + 1] > pc:
					func_name = self.symbol_table[keys[idx]] + (" + 0x%x" % (pc - keys[idx]))
					break
				elif keys[idx + 1] == pc:
					print "FUNCTION POINTER DETECTED for PC 0x%x" % (pc)
					func_name = "*FNCPTR_DETECTED*"
					break

			if func_name == '':
				if self.code_finish_address > pc:
					ret.append(self.symbol_table[keys[len(keys) - 1]] + (" + 0x%x" % (pc - keys[len(keys) - 1])))
				#else:
					#print "NO FUNCTION DETECTED for PC 0x%x" % (pc)
			elif func_name != "*FNCPTR_DETECTED*":
				ret.append(func_name)

		return ret


type_dictionary = {0:"READ", 1:"PREAD64", 2:"READV", 3:"PREADV", 4:"WRITE", 5:"PWRITE64", 6:"WRITEV", 7:"PWRITEV"}



# represents each system call.
class Syscall:
	# args: array of string
	def __init__(self, args, pcstat):
		self.timestamp = int(args[0])
		self.latency = int(args[1])
		self.filename = args[2]
		self.type = int(args[3])
		self.pos = int(args[4])
		self.size = int(args[5])
		pcs = map(lambda x: int(x, 16), args[6].split())
		self.pcs = pcstat.convert_pc_to_symbol(pcs)

	
	# prints the system call information to file.
	def print_syscall(self, f, f_pc):
		string = str(self.timestamp)
		string += "\t" + str(self.latency)
		string += "\t" + self.filename
		string += "\t" + type_dictionary[self.type]
		string += "\t" + str(self.pos)
		string += "\t" + str(self.size) + "\n"
		f.write(string)

		pc_string = ""
		for pc in self.pcs:
			pc_string += pc + "\n"
		f_pc.write(pc_string + "\n")



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

		# add syscall information to pc_dict
		syscall_list = list()
		pcs_string = pcs_into_string(syscall.pcs)
		if pcs_string in pcstat.pc_dict:
			syscall_list = pcstat.pc_dict[pcs_string]
		syscall_list.append(syscall)
		pcstat.pc_dict[pcs_string] = syscall_list

		# write converted system call information to new file.
		f = open("logs/log_" + syscall.filename.split("/")[-1], "a")
		f_pc = open("logs/pc_" + syscall.filename.split("/")[-1], "a")
		syscall.print_syscall(f, f_pc)

	pcstat.file_close()

	# analyze given syscalls

main()
