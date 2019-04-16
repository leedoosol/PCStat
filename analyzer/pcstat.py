# -*- coding:UTF-8 -*-
import os
import sys

'''
	Implementation of PCStat:
		analyze given log, which is in format:
			(timestamp, latency, filename, starting position, size, program contexts)
		analyze by program context and file to catch file I/O pattern and latency.
	
	sys.argv[1]: I/O syscall log file name
	sys.argv[2]: PC syscall log file name
	sys.argv[3]: base address filename
	sys.argv[4]: symbol table filename
'''

IO_WRAP_DEGREE = 3
PAGE_SIZE = 4096
SEQUENTIAL_THRESHOLD = 4

# temporary function for storing PC.
def pcs_into_string(pcs):
	ret = ''
	for pc in pcs:
		ret += pc + '\t'
	return ret



# represents the PCStat itself.
class PCStat:
	# initialization of PCStat.
	def __init__(self):
		print "PCStat - initialization started"

		self.pc_dict = dict()
		self.pc_counter = 0;
		self.syscalls_per_pc = dict()
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

		# get PC syscall log from file
		self.pc_syscall_table = dict()
		self.setup_pc_syscall_table()


	# get base address from file
	def get_base_address(self):
		f = open(sys.argv[3], "r")
		return int(f.readline().split()[2], 16)


	# setup symbol table
	def setup_symbol_table(self):
		f = open(sys.argv[4], "r")

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
	

	# read PC syscall log from file
	def setup_pc_syscall_table(self):
		f = open(sys.argv[2], "r")

		while True:
			line = f.readline()
			if not line:
				break

			line = line.split('\t')
			self.pc_syscall_table[line[1].strip()] = line[0].split()

	
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
			
			# check if the address is on upper side of actual code section.
			if pc <= keys[0]:
				continue			

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


	# submit PC and convert into PC code number.
	def convert_pc_symbol_into_code(self, pc_symbols):
		keys = self.pc_dict.keys()
		code = -1
		
		for symbol_string in keys:
			symbols = symbol_string.split('\t')
			length = min(len(symbols), len(pc_symbols))
			common_pc_length = 0
			
			# get common PC sequence
			for i in range(length):
				if i < len(pc_symbols):
					if pc_symbols[i] == symbols[i]:
						common_pc_length += 1
					else:
						# provide 1 more readahead in case of noise PCs.
						if i < len(pc_symbols) - 1 and pc_symbols[i + 1] == symbols[i]:
							pc_symbols.pop(i)
							common_pc_length += 1
						else:
							break

			# set this as the common PC if common length is longer than wrapup degree.
			if common_pc_length > IO_WRAP_DEGREE:
				code = self.pc_dict[symbol_string]

				# get new common PC sequence
				pc_seq = symbols[0:common_pc_length]

				# remove previous pc sequence
				self.pc_dict.pop(symbol_string, None)
				
				# set new PC sequence
				self.pc_dict[pcs_into_string(pc_seq)] = code
				break

		# add new PC to pc_dict if there is no common sequence.
		if code == -1 and len(pc_symbols) > IO_WRAP_DEGREE:
			code = self.pc_counter
			self.pc_counter += 1
			self.pc_dict[pcs_into_string(pc_symbols)] = code

		return code


	# write PC table and log to file.
	def syscall_log(self):
		# write PC table to file
		pc_table_file = open("logs/syscall_table.log", "w")
		sorted_tuples = sorted(self.pc_dict.items(), key=lambda x:x[1])
		
		for pc_string, pc_code in sorted_tuples:
			pcs = pc_string.split("\t")

			string = str(pc_code)
			for pc in pcs:
				string += "\t" + pc + "\n"
			string += "\n"
			
			pc_table_file.write(string)

		pc_table_file.close()

		# write each PC's I/O syscall
		for pc_code in self.syscalls_per_pc.keys():
			f = open("logs/pc_" + str(pc_code) + ".log", "w")
			
			syscalls = self.syscalls_per_pc[pc_code]
			for syscall in syscalls:
				syscall.print_syscall(f, None)

			f.close()


	# analyze given PCs - find pattern.
	def analyze_syscall(self):
		for pc_code in self.syscalls_per_pc.keys():
			# get syscalls per pc_code
			syscalls = self.syscalls_per_pc[pc_code]

			# hint for given sequence of system call
			is_sequential_io = False
			has_high_locality = False

			locality_dict = dict()

			# check locality
			seq_depth = 0
			seq_depth_list = list()
			cur_sector = syscalls[0].pos
			block_access_list = list()
			cnt = 0

			# traverse through every system call.
			for syscall in syscalls:
				cnt += 1
				sector = syscall.pos
				size = syscall.size

				# add this block's access time.
				block_access_list.append(sector - (sector % PAGE_SIZE))

				# set sequentiality depth if matches.
				if sector == cur_sector:
					seq_depth += 1
					if cnt == len(syscalls):
						seq_depth_list.append(seq_depth)
				else:
					seq_depth_list.append(seq_depth)
					seq_depth = 1
				
				cur_sector = sector + size

			# set this PC to 'sequential' if average of seq_depth_list is larger than threshold.
			if sum(seq_depth_list) / (float)(len(seq_depth_list)) >= SEQUENTIAL_THRESHOLD:
				is_sequential_io = True

			# calculate average reference recency.
			recent_visited_blocks = list()
			ref_recency = 0.0
			avg_ref_recency = 0.0
			undef = 0

			# R_i : p_i / (|L_i| - 1)      if |L_i| > 1
			#       0.5                    if |L_i| == 1
			#       undef                  if first access
			for sector in block_access_list:
				# check this sequence as undefined.
				if sector not in recent_visited_blocks:
					undef += 1
					recent_visited_blocks.append(sector)
				# no need to remove element from list.
				elif len(recent_visited_blocks) == 1:
					ref_recency += 0.5
				# calculate locality, remove, and append sector number.
				else:
					ref_recency += block_access_list.index(sector) / (float)(len(recent_visited_blocks) - 1)
					recent_visited_blocks.remove(sector)
					recent_visited_blocks.append(sector)

			# avoid divide-by-zero-exception.
			if undef == len(block_access_list):
				avg_ref_recency = 0
			else:
				avg_ref_recency = ref_recency / (float)(len(block_access_list) - undef)

			# set this PC to 'high locality' if average reference recency is equal or above 0.4.
			if avg_ref_recency >= 0.4:
				has_high_locality = True

			# log
			print "PC Code", pc_code, ": sequentiality", is_sequential_io, ", high locality", has_high_locality


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

		pcs = args[6].split()
		pc_string = ''
		if pcs[0] == 'PC_SIG':
			pc_splited = pcstat.pc_syscall_table[pcs[1]]
		else:
			pc_splited = pcs

		pcs = map(lambda x: int(x, 16), pc_splited)
		self.pcs = pcstat.convert_pc_to_symbol(pcs)

	
	# prints the system call information to file.
	def print_syscall(self, f, f_pc):
		string = str(self.timestamp)
		#string += "\t" + str(self.latency)
		string += "\t" + type_dictionary[self.type]
		string += "\t" + str(self.pos)
		string += "\t" + str(self.size)
		string += "\t" + self.filename + "\n"
		f.write(string)

		if f_pc is not None:
			pc_string = ""
			for pc in self.pcs:
				pc_string += pc + "\n"
			f_pc.write(pc_string + "\n")



# main function.
def main():
	pcstat = PCStat()
	logs = dict()

	while True:
		line = pcstat.readline()
		if not line:
			break

		syscall = Syscall(line.split("\t"), pcstat);

		# block unnecessary /dev/pts related syscalls
		if "/dev/pts" in syscall.filename:
			continue

		# add syscall information to pc_dict
		code = pcstat.convert_pc_symbol_into_code(syscall.pcs)
		if code >= 0:
			syscall_list = list()
			if code in pcstat.syscalls_per_pc:
				syscall_list = pcstat.syscalls_per_pc[code]
			syscall_list.append(syscall)
			pcstat.syscalls_per_pc[code] = syscall_list

		# write converted system call information to new file.
		#f = open("logs/log_" + syscall.filename.split("/")[-1], "a")
		#f_pc = open("logs/pc_" + syscall.filename.split("/")[-1], "a")
		#syscall.print_syscall(f, f_pc)

	pcstat.file_close()

	# analyze given syscalls
	pcstat.syscall_log()
	pcstat.analyze_syscall()

main()
