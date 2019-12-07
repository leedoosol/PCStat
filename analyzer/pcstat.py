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

	Explanation for Terminology '(User-level) PC Syscall':
		'PC syscall' records the PC of given point by user(programmer).
		It exists for the detection of the real PC:
			ex) I/O thread environment
'''

type_dictionary = {0:"READ", 1:"PREAD64", 2:"READV", 3:"PREADV", 4:"WRITE", 5:"PWRITE64", 6:"WRITEV", 7:"PWRITEV"}
IO_WRAP_DEGREE = 1
PAGE_SIZE = 4096
SEQUENTIAL_THRESHOLD = 4
PC_INTO_SIGNATURE = True
MAKE_CONFIGURATION = True
MAJOR_PC_IO_SIZE = PAGE_SIZE * 128

# temporary function for storing PC.
def symbols_into_string(pcs):
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
		self.file_dict = dict()

		# read log file
		self.log_file = open(sys.argv[1], "r")

		# get the base address of binary
		self.base_address = self.get_base_address()
		print "BASE ADDRESS: %x" % self.base_address
		self.code_finish_address = 0

		# get the symbol table from binary ELF
		if PC_INTO_SIGNATURE == False:
			self.symbol_table = dict()
			self.setup_symbol_table()

		# get User-level PC syscall log from file
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

		keys = self.symbol_table.keys()
		keys.sort()
		self.sorted_keys = keys
	

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
	# keys[]의 value는 아마도 pc값이고, 
	# 이 함수의 intput: 한 system call의 거쳐온 pc값들, output: func_name들로 바꾼 값들
	# 이렇게 거르는 이유는, 크기가 0인 function pointer(허수 함수들)을 피하기 위함으로 보인다.
	def convert_pc_to_symbol(self, pcs):
		ret = list()
		keys = self.sorted_keys

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
					func_name = self.symbol_table[keys[idx]]# + (" + 0x%x" % (pc - keys[idx]))
					break
				elif keys[idx + 1] == pc:
					#print "FUNCTION POINTER DETECTED for PC 0x%x" % (pc)
					func_name = "*FNCPTR_DETECTED*"
					break
					
			if func_name == '':
				if self.code_finish_address > pc:
					ret.append(self.symbol_table[keys[len(keys) - 1]]) # + (" + 0x%x" % (pc - keys[len(keys) - 1])))
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
			
			# get common PC sequence
			ahead = 0
			common_symbols = []
			for i in range(length):
				if i < len(pc_symbols) and i + ahead < len(symbols):
					if pc_symbols[i] == symbols[i + ahead]:
						common_symbols.append(pc_symbols[i])
					elif PC_INTO_SIGNATURE == False:
						# provide 1 more readahead in case of noise PCs.
						if i < len(pc_symbols) - 1:
							if pc_symbols[i + 1] == symbols[i + ahead]:
								common_symbols.append(pc_symbols[i + 1])
								pc_symbols.pop(i)
							elif i + ahead < len(symbols) - 1 and pc_symbols[i] == symbols[i + ahead + 1]:
								common_symbols.append(pc_symbols[i])
								ahead += 1
							elif i + ahead < len(symbols) - 1 and pc_symbols[i + 1] == symbols[i + ahead + 1]:
								common_symbols.append(pc_symbols[i + 1])
								pc_symbols.pop(i)
								ahead += 1
						else:
							break


			# set this as the common PC if common length is longer than wrapup degree.
			if len(common_symbols) > IO_WRAP_DEGREE:
				code = self.pc_dict[symbol_string]

				# remove previous pc sequence
				self.pc_dict.pop(symbol_string, None)
				
				# set new PC sequence
				self.pc_dict[symbols_into_string(common_symbols)] = code
				break

		# add new PC to pc_dict if there is no common sequence.
		if code == -1 and len(pc_symbols) > IO_WRAP_DEGREE:
			code = self.pc_counter
			self.pc_counter += 1
			self.pc_dict[symbols_into_string(pc_symbols)] = code

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


	# get block access times from pcstat
	def get_block_access_times(self, filename, pos):
		block_access_times = list()

		if filename in self.file_dict.keys():
			blocks = self.file_dict[filename]
			if pos in blocks:
				block_access_times = blocks[pos]

		return block_access_times
	

	# set block access time to pcstat
	def set_block_access_times(self, filename, pos, block_access_times):
		if filename not in self.file_dict.keys():
			self.file_dict[filename] = dict()

		blocks = self.file_dict[filename]
		blocks[pos] = block_access_times
		self.file_dict[filename] = blocks

	# file은 block들로 이루어져 있고, 각 block마다 접근 된 시간들을 모두 더해서 접근된 횟수로 나눈다. 자주 참조되는 block의 경우
	# 이 값의 크기는 높을 것으로 
	def calculate_block_reref_time(self):
		for filename in self.file_dict.keys():
			blocks = self.file_dict[filename]
			for sector_no in blocks.keys():
				block_ref_times = blocks[sector_no]
				block_ref_times.sort()
				sum_reref_times = 0
				reref_no = 0
				for i in range(len(block_ref_times) - 1):
					reref_time = block_ref_times[i + 1] - block_ref_times[i]
					if reref_time < 100000000:
						sum_reref_times += reref_time
						reref_no += 1

				if reref_no == 0:
					blocks[sector_no] = -100000000
				else:
					blocks[sector_no] = float(sum_reref_times) / float(reref_no)


	# analyze given PCs - find pattern.
	def analyze_syscall(self):
		pc_log_file = open("pc_log.log", "w")
		for pc_code in self.syscalls_per_pc.keys():
			# get syscalls per pc_code
			syscalls = self.syscalls_per_pc[pc_code]

			# check locality
			seq_depth = 0
			seq_depth_list = list()
			cur_sector = syscalls[0].pos
			filename = syscalls[0].filename
			block_access_list = list()
			cnt = 0
			io_type = 0
			total_io_size = 0
			total_latency = 0

			# traverse through every system call.
			for syscall in syscalls:
				cnt += 1
				sector = syscall.pos
				size = syscall.size
				io_type = syscall.type

				total_io_size += size
				total_latency += syscall.latency

				# set sequentiality depth if matches.
				# sequentiality doesnt matter when I/O size is too small, so ignore small I/Os.
				# RockDB의 경우에 size가 PAGE_SIZE보다 작은데도 불구하고 연속성을 보이는 경우가 있어서
				# 나의 코드에서는 'size >= PAGE_SIZE' 부분은 뺀다
				if filename == syscall.filename and sector == cur_sector and size >= PAGE_SIZE:
					seq_depth += 1
					if cnt == len(syscalls):
						seq_depth_list.append(seq_depth)
				else:
					seq_depth_list.append(seq_depth)
					seq_depth = 1
				
				cur_sector = sector + size
				filename = syscall.filename

			# ignore minor PCs.
			if total_io_size < MAJOR_PC_IO_SIZE:
				continue

			avg_io_size = total_io_size / float(len(syscalls))
			has_io_pattern = False

			# create PC information and write to file.
			pc_info = ""
			if MAKE_CONFIGURATION:
				pc_info = str(pc_code) + " "
			else:
				pc_info = "PC " + str(pc_code)
				pc_info += "\t\ttype " + type_dictionary[io_type]
				pc_info += "\t\tavg I/O size %.2f\tavg latency %.2f" % (avg_io_size, total_latency / float(len(syscalls)))
				pc_info += "\t\tI/O Pattern: "

			# set this PC to 'sequential' if average of seq_depth_list is larger than threshold.
			if io_type <= 3: # only give hint on SEQ/RAND for reads. writes cannot be affected.
				avg_seq_depth = sum(seq_depth_list) / (float)(len(seq_depth_list))
				if avg_seq_depth >= 4:
					if MAKE_CONFIGURATION:
						pc_info += "1 "
					else:
						pc_info += "SEQUENTIAL "
					has_io_pattern = True
				elif avg_seq_depth <= 1 and avg_io_size <= PAGE_SIZE * 4:
					# random only has meaning when I/O is small enough.
					if MAKE_CONFIGURATION:
						pc_info += "2 "
					else:
						pc_info += "RANDOM "
					has_io_pattern = True

			# get block's access frequency
			avg_ref_recency = -100000000
			if syscall.filename in self.file_dict.keys():
				blocks = self.file_dict[syscall.filename]
				for i in range(0, syscall.size / PAGE_SIZE):
					sector = (syscall.pos % PAGE_SIZE) + (i * PAGE_SIZE)
					#syscall이 접근한 sector(block)를 blocks배열에서 찾는다. 그 블럭이 재참조가 잘 되는 블럭인지 봄
					if sector in blocks: 
						if avg_ref_recency < blocks[sector]:
							avg_ref_recency = blocks[sector]

			avg_ref_recency = avg_ref_recency / 100000000.0
			if avg_ref_recency < 0:
				if MAKE_CONFIGURATION:
					pc_info += "3"
				else:
					pc_info += "DONTNEED"
				has_io_pattern = True
			elif avg_ref_recency < 0.001:
				if MAKE_CONFIGURATION:
					pc_info += "4"
				else:
					pc_info += "WILLNEED"
				has_io_pattern = True
			
			pc_info += "\n"

			if has_io_pattern:
				pc_log_file.write(pc_info)

		pc_log_file.close()


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
		self.code = 0

		pcs = args[6].split()
		pc_string = ''
		
		# id 'PC_SIG' : this requires the PC from user-level PC system call.
		if pcs[0] == 'PC_SIG':
			pc_splited = pcstat.pc_syscall_table[pcs[1]]
		else:
			pc_splited = pcs

		pcs = map(lambda x: int(x, 16), pc_splited)
		if PC_INTO_SIGNATURE:
			self.code = sum(pcs)
		else:
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
	num_syscall = 0

	while True:
		#1.  시스템콜 하나가 만들어낸 한 줄 을 읽는다.
		line = pcstat.readline()
		if not line:
			break

		num_syscall += 1
		if num_syscall % 10000 == 0:
			print num_syscall, "syscalls has been calculated"

		syscall = Syscall(line.split("\t"), pcstat);

		# block unnecessary /dev/pts related syscalls
		if "/dev/pts" in syscall.filename:
			continue
		if "/sys/devices" in syscall.filename:
			continue
		if "/proc/" in syscall.filename:
			continue
		if "/usr/share/" in syscall.filename:
			continue

		# add syscall information to pc_dict
	   	# 2. 그 system call이 겪은 pc들에 해당하는 code값을 convert_pc_symbol_into_code()에서 pc_dict[]에서 찾아서 
	 	# code값을 리턴한다. 
		if PC_INTO_SIGNATURE:
			code = syscall.code
		else:
			code = pcstat.convert_pc_symbol_into_code(syscall.pcs)
		if code >= 0:
			# 3. 그 code에 해당하는 syscall_list(즉, func name으로 확인까지 마친(common_symbols확인))를 가지고 분석
			syscall_list = list()
			if code in pcstat.syscalls_per_pc:
				syscall_list = pcstat.syscalls_per_pc[code]
			syscall_list.append(syscall)
			pcstat.syscalls_per_pc[code] = syscall_list

			# add data access time to file_dict
			# 만일 size가 5000이라면, 두개의 블럭(블럭사이즈:4096)에 접근하는 것이니 두개의 블럭에 대해 시간 갱신
			# pos=100, size=4097이라면, pos = 100, 4196이 된다.
			for i in range(0, syscall.size / PAGE_SIZE):
				pos = (syscall.pos % PAGE_SIZE) + (PAGE_SIZE * i)
				block_access_times = pcstat.get_block_access_times(syscall.filename, pos)
				block_access_times.append(syscall.timestamp)
				pcstat.set_block_access_times(syscall.filename, pos, block_access_times)

	pcstat.file_close()

	# calculate each block's average re-reference time
	pcstat.calculate_block_reref_time();

	# analyze given syscalls
	if PC_INTO_SIGNATURE == False:
		pcstat.syscall_log()
	pcstat.analyze_syscall()

main()
