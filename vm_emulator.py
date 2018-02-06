import sys
import pydot

class Node():

	def __init__(self, label):
		# The label associated to this node
		self.label = label
		# The list of instructions contained in the node
		self.insn = []
		# The list of children of the node
		self.children = []

	def getStartAddress(self):
		# Get the start address of the node
		return int(self.label.replace("LABEL_", ""), 16)

	def addChild(self, label):
		if label not in self.children:
			self.children.append(label)

	def getChildren(self):
		# Beware to not modify the list
		return self.children

	def addInstruction(self, addr, insn):
		# Add a new instruction to the list
		self.insn.append((addr,insn))

	def getARM(self):
		arm = self.label + "\\l\\l"
		for instruction in self.insn:
			if "nop" not in instruction[1]:
				arm += " "*4 + (hex(instruction[0]) + " "*2) + (instruction[1] + "\\l")
		return arm

	def getPydotNode(self):
		node = pydot.Node(self.getARM(), shape="box", style="filled", fillcolor="#00000000")
		return node

class VirtualMachine():

	def __init__(self, bytecode, bytecode_size):

		# Initialize bytecode

		self.VM_BYTECODE_PTR = bytecode
		self.VM_BYTECODE_SIZE = bytecode_size

		# Initialize virtual instruction pointer

		self.VM_EIP = None

		# Initialize virtual registers context

		self.VM_REG_CTX = {
			"r0" : 0,
			"r1" : 0,
			"r2" : 0,
			"r3" : 0,
			"r4" : 0,
			"r5" : 0,
			"r6" : 0,
			"r7" : 0,
			"r8" : 0,
			"r9" : 0,
			"r10" : 0,
			"r11" : 0,
			"r12" : 0,
			"lr" : 0,
			"pc" : 0,
			"sp" : 0
		}

		self.ARM_REGS = [ "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12", "lr", "pc", "sp" ]

		# Initialize virtual stack

		self.VM_STACK = []

		# Initialize self.TMP_VAR_1, self.TMP_VAR_2

		self.TMP_VAR_1 = None
		self.TMP_VAR_2 = None

		# Control flow: list of unvisited nodes

		self.currentNode = None
		self.unvisited = [ 0 ]
		self.nodes = {}

	def getByte(self, disp = 0):
		addr = self.VM_EIP + disp
		res = int(self.VM_BYTECODE_PTR[addr], 16)
		return res

	def getWord(self, disp = 0):
		addr = self.VM_EIP + disp
		b1, b2 = self.getByte(disp), self.getByte(disp + 1)
		res = b1 | (b2 << 8)
		return res

	def getDword(self, disp = 0):
		addr = self.VM_EIP + disp
		w1, w2 = self.getWord(disp), self.getWord(disp + 2)
		res = w1 | (w2 << 16)
		return res

	def incVMEIP(self, amount):

		self.VM_EIP += amount

	# These 2 functions are implementing conditional branching

	def determineNewVM_EIP(self, offset):

		offset >>= 2
		print "; OFFSET = " + hex(offset)

		OLD_VM_EIP = self.VM_EIP
		self.VM_EIP = 0

		COUNTER = 0

		while True:

			if self.VM_EIP > self.VM_BYTECODE_SIZE:
				return 0xFFFFFFFF

			byte = self.getByte()
			#print "byte = " + hex(byte)
			#print "VM_EIP = " + hex(self.VM_EIP)
			#print "COUNTER = " + hex(COUNTER)
			#raw_input()

			if byte == 2:
				self.incVMEIP(1)
				dword = self.getDword()
				if dword == 0xE:
					self.incVMEIP(12)
					continue
				else:
					self.incVMEIP(4)
					continue
			elif byte == 3:
				self.incVMEIP(5)
				continue
			elif byte == 1:
				self.incVMEIP(5)
				continue
			elif byte == 4:
				self.incVMEIP(5)
				continue
			elif byte == 0x1D:
				self.incVMEIP(9)
				continue
			elif byte == 0x22:
				self.incVMEIP(13)
				continue
			elif byte == 0x1E or byte == 0x1F:
				self.incVMEIP(13)
				continue
			elif byte == 0x24 or byte == 0x25:
				self.incVMEIP(13)
				continue
			elif byte != 0:
				self.incVMEIP(1)
				continue
			else:
				COUNTER += 1 # ADD R4, R4, #1
				self.incVMEIP(1)
				if COUNTER == offset:
					print "; VM_EIP = " + hex(self.VM_EIP)
					return OLD_VM_EIP
				else:
					continue

	def VIRTUAL_MACHINE_CONDITIONAL_JUMP(self, val):

		'''
		0x1E:

			subs r1, r5, 0x1f 				; N = 1, C = 0, Z = 0, r1 = 0xFFFFFFFF
			rsbs r4, r1, 0x0 				; N = 0, C = 0, Z = 0, r4 = 0x1
			adcs r4, r4, r1 				; N = 0, C = 1, Z = 1, r4 = 0x0
			subs r7, r5, 0x25				; N = 1, C = 0, Z = 0, r7 = 0xFFFFFFF9
			rsbs r6, r7, 0x0 				; N = 0, C = 0, Z = 0, r6 = 0x7
			adcs r6, r6, r7 				; N = 0, C = 1, Z = 1, r6 = 0x0

		0x1F:

			subs r1, r5, 0x1f 				; N = 0, C = 1, Z = 1, r1 = 0x0
			rsbs r4, r1, 0x0 				; N = 0, C = 1, Z = 1, r4 = 0x0
			adcs r4, r4, r1 				; N = 0, C = 0, Z = 0, r4 = 0x1
			subs r7, r5, 0x25 				; N = 1, C = 0, Z = 0, r7 = 0xFFFFFFFA
			rsbs r6, r7, 0x0 				; N = 0, C = 0, Z = 0, r6 = 0x6
			adcs r6, r6, r7 				; N = 0, C = 1, Z = 1, r6 = 0x0

		0x24:

			subs r1, r5, 0x1f 				; N = 0, C = 1, Z = 0, r1 = 0x5
			rsbs r4, r1, 0x0 				; N = 1, C = 0, Z = 0, r4 = 0xFFFFFFFB
			adcs r4, r4, r1 				; N = 0, C = 1, Z = 1, r4 = 0x0
			subs r7, r5, 0x25 				; N = 1, C = 0, Z = 0, r7 = 0xFFFFFFFF
			rsbs r6, r7, 0x0 				; N = 0, C = 0, Z = 0, r6 = 0x1
			adcs r6, r6, r7 				; N = 0, C = 1, Z = 1, r6 = 0x0

		0x25:

			subs r1, r5, 0x1f 				; N = 0, C = 1, Z = 0, r1 = 0x6
			rsbs r4, r1, 0x0 				; N = 1, C = 0, Z = 0, r4 = 0xFFFFFFFA
			adcs r4, r4, r1 				; N = 0, C = 1, Z = 1, r4 = 0x0
			subs r7, r5, 0x25 				; N = 1, C = 1, Z = 1, r7 = 0x0
			rsbs r6, r7, 0x0 				; N = 0, C = 1, Z = 1, r6 = 0x0
			adcs r6, r6, r7 				; N = 0, C = 0, Z = 0, r6 = 0x1

		'''

		# Determine destination label

		LR = self.VM_REG_CTX["lr"]
		curr_offset = self.getDword()
		print "curr_offset = " + hex(curr_offset)
		self.incVMEIP(4)
		label_type = self.getDword()
		print "label_type = " + hex(label_type)
		base_addr = LR - curr_offset
		LABEL_1, LABEL_2 = 0, 0

		if label_type == 0:
			self.incVMEIP(4)
			func_offset = self.getDword()
			LABEL_1 = base_addr + func_offset
			print "; LABEL_1 = " + hex(LABEL_1)
			self.incVMEIP(4)
		elif label_type == 1:
			self.incVMEIP(4)
			func_offset = self.getDword()
			OLD_VM_EIP = self.VM_EIP
			print "; search starting from: " + hex(self.VM_EIP)
			print "; pointing to: libjiagu.so + " + hex(self.getDword())
			print "; searching for 0xE1A00000 = end of bytecode"
			LABEL_1 = base_addr + func_offset
			print "; LABEL_1 = " + hex(LABEL_1)
			self.incVMEIP(4)

		# Determine jump destinations

		if val == 0x1E or val == 0x24:
			val_1 = 0x0
			val_2 = 0x0
		elif val == 0x1F:
			val_1 = 0x1
			val_2 = 0x0
		elif val == 0x25:
			val_1 = 0x0
			val_2 = 0x1

		print "; val_1 = " + hex(val_1)
		print "; val_2 = " + hex(val_2)

		if ((val_1 | val_2) or val == 0x24):
			offset_1 = self.getDword()
			print "; offset_1 = " + hex(offset_1)
			self.incVMEIP(4)
			offset_2 = self.getDword()
			print "; offset_2 = " + hex(offset_2)
			LABEL_1 = base_addr + offset_1
			LABEL_2 = base_addr + offset_2
			self.incVMEIP(4)
			print "; LABEL_1 = " + hex(LABEL_1)
			print "; LABEL_2 = " + hex(LABEL_2)

		# Determine jump type

		JUMP_OFFSET = LABEL_1 - (LR - 4)
		JUMP_OFFSET_FIXED = JUMP_OFFSET + (3 if (JUMP_OFFSET < 0) else 0)
		JUMP_INSTRUCTION, DESTINATION_LABEL_1, DESTINATION_LABEL_2 = None, None, None

		if JUMP_OFFSET % 4 == 0:
			# Z set, val == 0x1E
			if val == 0x1E: # R12
				JUMP_INSTRUCTION = "beq"
				DESTINATION_LABEL_1 = LABEL_1
				DESTINATION_LABEL_2 = self.VM_EIP
				print JUMP_INSTRUCTION + " " + hex(DESTINATION_LABEL_1) + " (" + hex(DESTINATION_LABEL_2) + ")"
				self.addInstruction(JUMP_INSTRUCTION + " " + hex(DESTINATION_LABEL_1) + " (" + hex(DESTINATION_LABEL_2) + ")")
			
			# Z not set, val == 0x1E or val == 0x1F
			if val_1:
				if LABEL_1 >= LABEL_2: # R12
					JUMP_INSTRUCTION = "bne"
					DESTINATION_LABEL_1 = LABEL_1
					DESTINATION_LABEL_2 = self.VM_EIP
					print JUMP_INSTRUCTION + " " + hex(DESTINATION_LABEL_1) + " (" + hex(DESTINATION_LABEL_2) + ")"
					self.addInstruction(JUMP_INSTRUCTION + " " + hex(DESTINATION_LABEL_1) + " (" + hex(DESTINATION_LABEL_2) + ")")
				else:
					JUMP_INSTRUCTION = "bne"
					DESTINATION_LABEL_1 = self.determineNewVM_EIP(JUMP_OFFSET_FIXED)
					DESTINATION_LABEL_2 = self.VM_EIP
					print JUMP_INSTRUCTION + " " + hex(DESTINATION_LABEL_2) + " (" + hex(DESTINATION_LABEL_1) + ")"
					self.addInstruction(JUMP_INSTRUCTION + " " + hex(DESTINATION_LABEL_2) + " (" + hex(DESTINATION_LABEL_1) + ")")
			
			# C set, val == 0x24 or val == 0x25
			if val_2:
				if LABEL_1 >= LABEL_2: # R12
					JUMP_INSTRUCTION = "bhi"
					DESTINATION_LABEL_1 = LABEL_1
					DESTINATION_LABEL_2 = self.VM_EIP
					print JUMP_INSTRUCTION + " " + hex(DESTINATION_LABEL_1) + " (" + hex(DESTINATION_LABEL_2) + ")"
					self.addInstruction(JUMP_INSTRUCTION + " " + hex(DESTINATION_LABEL_1) + " (" + hex(DESTINATION_LABEL_2) + ")")
				else:
					JUMP_INSTRUCTION = "bhi"
					DESTINATION_LABEL_1 = self.determineNewVM_EIP(JUMP_OFFSET_FIXED)
					DESTINATION_LABEL_2 = self.VM_EIP
					print JUMP_INSTRUCTION + " " + hex(DESTINATION_LABEL_1) + " (" + hex(DESTINATION_LABEL_2) + ")"
					self.addInstruction(JUMP_INSTRUCTION + " " + hex(DESTINATION_LABEL_1) + " (" + hex(DESTINATION_LABEL_2) + ")")
			else:

				# val != 0x24
				#if val != 0x24:
				#	JUMP_INSTRUCTION = "b??"
				#	DESTINATION_LABEL_1 = self.VM_EIP
				#	print JUMP_INSTRUCTION + " " + hex(DESTINATION_LABEL_1)
				#	self.addInstruction(JUMP_INSTRUCTION + " " + hex(DESTINATION_LABEL_1))
				# Z set or C not set, val == 0x24
				if val == 0x24:
					if LABEL_1 >= LABEL_2: # R12
						JUMP_INSTRUCTION = "bls"
						DESTINATION_LABEL_1 = LABEL_1
						DESTINATION_LABEL_2 = self.VM_EIP
						print JUMP_INSTRUCTION + " " + hex(DESTINATION_LABEL_1) + " (" + hex(DESTINATION_LABEL_2) + ")"
						self.addInstruction(JUMP_INSTRUCTION + " " + hex(DESTINATION_LABEL_1) + " (" + hex(DESTINATION_LABEL_2) + ")")
					else:
						JUMP_INSTRUCTION = "bls"
						DESTINATION_LABEL_1 = self.determineNewVM_EIP(JUMP_OFFSET_FIXED)
						DESTINATION_LABEL_2 = self.VM_EIP
						print JUMP_INSTRUCTION + " " + hex(DESTINATION_LABEL_1) + " (" + hex(DESTINATION_LABEL_2) + ")"
						self.addInstruction(JUMP_INSTRUCTION + " " + hex(DESTINATION_LABEL_1) + " (" + hex(DESTINATION_LABEL_2) + ")")
		else:
			JUMP_INSTRUCTION = "b"
			DESTINATION_LABEL_1 = LABEL_1
			print JUMP_INSTRUCTION + " " + hex(DESTINATION_LABEL_1)
			self.addInstruction(JUMP_INSTRUCTION + " " + hex(DESTINATION_LABEL_1))

		# Return the 2 destination addresses

		return DESTINATION_LABEL_1, DESTINATION_LABEL_2

	def VIRTUAL_MACHINE_SHIFT_LEFT(self):

		shift = self.getDword(2)
		self.incVMEIP(2)
		index = self.getDword(5)
		self.incVMEIP(5)
		reg = self.ARM_REGS[index]
		self.incVMEIP(4)
		print "shl " + reg + ", " + reg + ", " + hex(shift)
		self.addInstruction("shl " + reg + ", " + reg + ", " + hex(shift))
		return reg

	def VIRTUAL_MACHINE_SHIFT_RIGHT(self):

		shift = self.getDword(2)
		self.incVMEIP(2)
		index = self.getDword(5)
		self.incVMEIP(5)
		reg = self.ARM_REGS[index]
		self.incVMEIP(4)
		print "shr " + reg + ", " + reg + ", " + hex(shift)
		self.addInstruction("shr " + reg + ", " + reg + ", " + hex(shift))
		return reg

	def VIRTUAL_MACHINE_EXECUTE_MATHOP(self, val):

		math_op = self.getByte()

		if math_op == 1:
			self.TMP_VAR_1 = self.getDword(1)
			print "mov TMP_VAR_1, " + hex(self.TMP_VAR_1)
			self.addInstruction("mov TMP_VAR_1, " + hex(self.TMP_VAR_1))
			self.incVMEIP(5)
			return
		elif math_op == 2:
			op_dword = None
			if val == 0xC or val == 0xD:
				op_dword = self.getDword(1)
				if op_dword == 0xE:
					offset = self.getDword(5)
					base = self.getDword(9)
					self.incVMEIP(13)
					print "add TMP_VAR_1, TMP_VAR_1, pc"
					print "add TMP_VAR_1, TMP_VAR_1, " + hex(base - offset)
					self.addInstruction("add TMP_VAR_1, TMP_VAR_1, pc")
					self.addInstruction("add TMP_VAR_1, TMP_VAR_1, " + hex(base - offset))
					return
			else:
				if val == 0xF or val == 0x11:
					index = self.getDword(1)
					self.incVMEIP(5)
					reg = self.ARM_REGS[index]
					self.TMP_VAR_1 = reg
					print "mov TMP_VAR_1, " + reg
					self.addInstruction("mov TMP_VAR_1, " + reg)
					return
				if val == 0xA:
					index = self.getDword(1)
					reg = self.ARM_REGS[index]
					if not self.TMP_VAR_1:
						print "neg TMP_VAR_1, " + reg
						self.addInstruction("neg TMP_VAR_1, " + reg)
						self.TMP_VAR_1 = reg
					else:
						print "sub TMP_VAR_1, TMP_VAR_1, " + reg
						self.addInstruction("sub TMP_VAR_1, TMP_VAR_1, " + reg)
					self.incVMEIP(5)
					return
				elif val == 0xB:
					index = self.getDword(1)
					reg = self.ARM_REGS[index]
					if not self.TMP_VAR_1:
						print "mov TMP_VAR_1, " + reg
						self.addInstruction("mov TMP_VAR_1, " + reg)
						self.TMP_VAR_1 = reg
					else:
						print "sub TMP_VAR_1, " + reg + ", TMP_VAR_1"
						self.addInstruction("sub TMP_VAR_1, " + reg + ", TMP_VAR_1")
					self.incVMEIP(5)
					return
				elif val == 0x10:
					index = self.getDword(1)
					reg = self.ARM_REGS[index]
					self.TMP_VAR_1 = reg
					print "mvn TMP_VAR_1, " + reg
					self.addInstruction("mvn TMP_VAR_1, " + reg)
					self.incVMEIP(5)
					return
				elif val == 0x12:
					index = self.getDword(1)
					reg = self.ARM_REGS[index]
					if not self.TMP_VAR_1:
						print "mov TMP_VAR_1, 0x0"
						self.addInstruction("mov TMP_VAR_1, 0x0")
						self.TMP_VAR_1 = reg
					else:
						print "and TMP_VAR_1, TMP_VAR_1, " + reg
						self.addInstruction("and TMP_VAR_1, TMP_VAR_1, " + reg)
					self.incVMEIP(5)
					return
				elif val == 0x13:
					index = self.getDword(1)
					reg = self.ARM_REGS[index]
					if not self.TMP_VAR_1:
						print "mov TMP_VAR_1, " + reg
						self.addInstruction("mov TMP_VAR_1, " + reg)
						self.TMP_VAR_1 = reg
					else:
						print "orr TMP_VAR_1, TMP_VAR_1, " + reg
						self.addInstruction("orr TMP_VAR_1, TMP_VAR_1, " + reg)
					self.incVMEIP(5)
					return
				elif val == 0x14:
					index = self.getDword(1)
					reg = self.ARM_REGS[index]
					if not self.TMP_VAR_1:
						print "mov TMP_VAR_1, " + reg
						self.addInstruction("mov TMP_VAR_1, " + reg)
						self.TMP_VAR_1 = reg
					else:
						print "eor TMP_VAR_1, TMP_VAR_1, " + reg
						self.addInstruction("eor TMP_VAR_1, TMP_VAR_1, " + reg)
					self.incVMEIP(5)
					return
				# ---------------------------------------------------------------- 63
				val_2 = val & 0xFFFFFFFD;
				if (val_2 != 0x80 and val != 0x88):
					if (val_2 == 0x81 or val == 0x89):
						op_dword = self.getDword(1)
						if op_dword == 0xE:
							offset = self.getDword(5)
							base = self.getDword(9)
							print "sub TMP_VAR_1, TMP_VAR_1, pc"
							print "add TMP_VAR_1, TMP_VAR_1, " + hex(base - offset)
							self.addInstruction("sub TMP_VAR_1, TMP_VAR_1, pc")
							self.addInstruction("add TMP_VAR_1, TMP_VAR_1, " + hex(base - offset))
							self.incVMEIP(13)
							return
						else:
							reg = self.ARM_REGS[op_dword]
							print "sub TMP_VAR_1, " + reg + ", TMP_VAR_1"
							self.addInstruction("sub TMP_VAR_1, " + reg + ", TMP_VAR_1")
							self.incVMEIP(5)
							return
					# ---------------------------------------------------------------- 87
					elif val_2 == 0x84:
						index = self.getDword(1)
						reg = self.ARM_REGS[index]
						if not self.TMP_VAR_1:
							self.TMP_VAR_1 = reg
							print "mov TMP_VAR_1, " + reg
							self.addInstruction("mov TMP_VAR_1, " + reg)
						else:
							print "add TMP_VAR_1, TMP_VAR_1, " + reg
							self.addInstruction("add TMP_VAR_1, TMP_VAR_1, " + reg)
						self.incVMEIP(5)
						return
					elif val_2 != 0x85:
						if val == 0x23:
							index = self.getDword(1)
							reg =self.ARM_REGS[index]
							print "shl TMP_VAR_1, 0xFFFFFFFF, TMP_VAR_1"
							print "and TMP_VAR_1, TMP_VAR_1, " + reg
							self.addInstruction("shl TMP_VAR_1, 0xFFFFFFFF, TMP_VAR_1")
							self.addInstruction("and TMP_VAR_1, TMP_VAR_1, " + reg)
							self.incVMEIP(5)
							#print "WTF is this?!"
							#quit()
						return
					# ---------------------------------------------------------------- 105
					index = self.getDword(1)
					reg = self.ARM_REGS[index]
					print "sub TMP_VAR_1, " + reg + ", TMP_VAR_1"
					self.addInstruction("sub TMP_VAR_1, " + reg + ", TMP_VAR_1")
					self.incVMEIP(4)
					return
				# ---------------------------------------------------------------- 109
				op_dword = self.getDword(1)
				if op_dword == 0xE:
					offset = self.getDword(5)
					base = self.getDword(9)
					self.incVMEIP(13)
					print "add TMP_VAR_1, TMP_VAR_1, pc"
					print "add TMP_VAR_1, TMP_VAR_1, " + hex(base - offset)
					self.addInstruction("add TMP_VAR_1, TMP_VAR_1, pc")
					self.addInstruction("add TMP_VAR_1, TMP_VAR_1, " + hex(base - offset))
					return
			# -------------------------------------------------------------------- 122
			#op_dword = self.getDword(1)
			reg = self.ARM_REGS[op_dword]
			if not self.TMP_VAR_1:
				self.TMP_VAR_1 = reg
				print "mov TMP_VAR_1, " + reg
				self.addInstruction("mov TMP_VAR_1, " + reg)
			else:
				print "add TMP_VAR_1, TMP_VAR_1, " + reg
				self.addInstruction("add TMP_VAR_1, TMP_VAR_1, " + reg)
			self.incVMEIP(5)
			return
		elif math_op == 3:
			index = self.getDword(1)
			reg = self.ARM_REGS[index]
			print "mov TMP_VAR_2, " + reg
			self.addInstruction("mov TMP_VAR_2, " + reg)
			self.incVMEIP(5)
			return
		elif math_op == 4:
			if val == 0x80 or val == 0x81:
				index = self.getDword(1)
				reg = self.ARM_REGS[index]
				print "ldr " + reg + ", [TMP_VAR_1]"
				self.addInstruction("ldr " + reg + ", [TMP_VAR_1]")
				self.incVMEIP(5)
				return
			elif val == 0x82 or val == 0x83:
				index = self.getDword(1)
				reg = self.ARM_REGS[index]
				print "ldrb " + reg + ", [TMP_VAR_1]"
				self.addInstruction("ldrb " + reg + ", [TMP_VAR_1]")
				self.incVMEIP(5)
				return
			if val == 0x84 or val == 0x85:
				print "str TMP_VAR_2, [TMP_VAR_1]"
				self.addInstruction("str TMP_VAR_2, [TMP_VAR_1]")
				self.incVMEIP(5)
				return
			if val == 0x86 or val == 0x87:
				print "strb TMP_VAR_2, [TMP_VAR_1]"
				self.addInstruction("strb TMP_VAR_2, [TMP_VAR_1]")
				self.incVMEIP(5)
				return
			# --------------------------------------------- 169
			if (val == 0x11 or val == 0xD):
				index = self.getDword(1)
				reg = self.ARM_REGS[index]
				#print "moveq " + reg + ", TMP_VAR_1"
				#self.addInstruction("moveq " + reg + ", TMP_VAR_1")
				print "movne " + reg + ", TMP_VAR_1"
				self.addInstruction("movne " + reg + ", TMP_VAR_1")
				self.incVMEIP(5)
				#print "WTF is this?!"
				#quit()
				return
			elif val == 0x88 or val == 0x89:
				index = self.getDword(1)
				reg = self.ARM_REGS[index]
				print "moveq " + reg + ", [TMP_VAR_1]"
				self.addInstruction("moveq " + reg + ", [TMP_VAR_1]")
				self.incVMEIP(5)
				print "WTF is this?!"
				#quit()
				return
			# --------------------------------------------- 185
			index = self.getDword(1)
			reg = self.ARM_REGS[index]
			print "mov " + reg + ", TMP_VAR_1"
			self.addInstruction("mov " + reg + ", TMP_VAR_1")
			self.incVMEIP(5)
			return

	def VIRTUAL_MACHINE_EXECUTE_SHIFTED_MATHOP(self, val):

		shift_type = self.getDword()
		if shift_type == 0x6:
			while True:
				reg = self.VIRTUAL_MACHINE_SHIFT_LEFT()
				self.TMP_VAR_1 = reg
				print "mov TMP_VAR_1, " + reg
				self.addInstruction("mov TMP_VAR_1, " + reg)
				self.VIRTUAL_MACHINE_EXECUTE_MATHOP(val)
				if self.getByte(-5) == 4:
					break
		elif shift_type == 0x7:
			while True:
				reg = self.VIRTUAL_MACHINE_SHIFT_RIGHT()
				self.TMP_VAR_1 = reg
				print "mov TMP_VAR_1, " + reg
				self.addInstruction("mov TMP_VAR_1, " + reg)
				self.VIRTUAL_MACHINE_EXECUTE_MATHOP(val)
				if self.getByte(-5) == 4:
					break
		else:
			while True:
				self.VIRTUAL_MACHINE_EXECUTE_MATHOP(val)
				if self.getByte(-5) == 4:
					break

	def VIRTUAL_MACHINE_MATHOPS(self, val1, val2):

		val = self.getByte()
		if val == 0xC:
			self.incVMEIP(1)
			byte = self.getByte()
			if byte == 0x1A:
				self.incVMEIP(1)
				while True:
					self.VIRTUAL_MACHINE_EXECUTE_MATHOP(0xC)
					if self.getByte(-5) == 4:
						break
			else:
				self.VIRTUAL_MACHINE_EXECUTE_SHIFTED_MATHOP(val1)
		elif val == 0xB:
			self.incVMEIP(1)
			byte = self.getByte()
			if byte == 0x1A:
				self.incVMEIP(1)
				while True:
					self.VIRTUAL_MACHINE_EXECUTE_MATHOP(0xB)
					if self.getByte(-5) == 4:
						break
			else:
				self.VIRTUAL_MACHINE_EXECUTE_SHIFTED_MATHOP(val2)
		else:
			self.VIRTUAL_MACHINE_EXECUTE_MATHOP(val1)

	def singleStep(self):

		# Get a VM_EIP from the unvisited ones

		if self.VM_EIP == None:
			if not len(self.unvisited):
				return False
			else:
				self.VM_EIP = self.unvisited.pop()
				self.currentNode = "LABEL_" + hex(self.VM_EIP)
				self.nodes.update({ self.currentNode : Node(self.currentNode) })

		print self.unvisited

		# Save the current instruction address

		self.current_VM_EIP = self.VM_EIP

		# Get the handler index used in the switch

		HANDLER_INDEX = self.getByte()

		print "LABEL_" + hex(self.VM_EIP) + ":"
		print "HANDLER_INDEX = " + hex(HANDLER_INDEX)

		# Execute the correct handler

		if HANDLER_INDEX == 0x0:
			# NOP
			self.incVMEIP(1)
			print "nop"
			self.addInstruction("nop")
		elif HANDLER_INDEX == 0x6:
			self.incVMEIP(1)
			self.TMP_VAR_2 = self.VIRTUAL_MACHINE_SHIFT_LEFT()
			self.incVMEIP(1)
			index = self.getDword()
			reg = self.ARM_REGS[index]
			print "mov " + reg + ", " + self.TMP_VAR_2
			self.incVMEIP(4)
		elif HANDLER_INDEX == 0xA:
			self.incVMEIP(1)
			op_type = self.getByte()
			self.TMP_VAR_1, self.TMP_VAR_2 = None, None
			if op_type == 2:
				index = self.getDword(1)
				self.incVMEIP(5)
				reg = self.ARM_REGS[index]
				self.TMP_VAR_1 = reg
				print "mov TMP_VAR_1, " + reg
				op_type = self.getByte()
			elif op_type == 1:
				imm = self.getDword(1)
				self.incVMEIP(5)
				self.TMP_VAR_1 = imm
				print "mov TMP_VAR_1, " + reg
				op_type = self.getByte()
			if op_type:
				while True:
					self.VIRTUAL_MACHINE_EXECUTE_MATHOP(HANDLER_INDEX)
					if not self.getByte():
						break
		elif HANDLER_INDEX == 0xB:
			self.TMP_VAR_1, self.TMP_VAR_2 = None, None
			self.incVMEIP(1)
			while True:
				shift_type = self.getByte()
				if not shift_type:
					break
				if shift_type == 0x6:
					self.VIRTUAL_MACHINE_SHIFT_LEFT()
				elif shift_type == 0x7:
					self.VIRTUAL_MACHINE_SHIFT_RIGHT()
				else:
					self.VIRTUAL_MACHINE_EXECUTE_MATHOP(HANDLER_INDEX)
		elif HANDLER_INDEX == 0xC:
			self.TMP_VAR_1, self.TMP_VAR_2 = None, None
			self.incVMEIP(1)
			while True:
				shift_type = self.getByte()
				if not shift_type:
					break
				if shift_type == 0x6:
					self.VIRTUAL_MACHINE_SHIFT_LEFT()
				elif shift_type == 0x7:
					self.VIRTUAL_MACHINE_SHIFT_RIGHT()
				else:
					self.VIRTUAL_MACHINE_EXECUTE_MATHOP(HANDLER_INDEX)
		elif HANDLER_INDEX == 0xD:
			self.TMP_VAR_1, self.TMP_VAR_2 = None, None
			self.incVMEIP(1)
			while True:
				shift_type = self.getByte()
				if not shift_type:
					break
				if shift_type == 0x6:
					self.VIRTUAL_MACHINE_SHIFT_LEFT()
				elif shift_type == 0x7:
					self.VIRTUAL_MACHINE_SHIFT_RIGHT()
				else:
					self.VIRTUAL_MACHINE_EXECUTE_MATHOP(HANDLER_INDEX)
		elif HANDLER_INDEX == 0xE:
			# SUBS REG, IMM32 -> CPSR is updated
			self.incVMEIP(1)
			num_ops = self.getByte()
			srcs = []
			# Execute a compare: CMP = SUBS REG1, VAL1
			while num_ops:
				while True:
					if num_ops == 1:
						srcs.append(hex(self.getDword(1)))
						self.incVMEIP(5)
					elif num_ops == 2:
						index = self.getDword(1)
						self.incVMEIP(5)
						srcs.append(self.ARM_REGS[index])
					elif num_ops == 0:
						break
					num_ops = self.getByte()
			# Print the comparison
			if len(srcs) == 2:
				print "cmp " + srcs[1] + ", " + srcs[0]
				self.addInstruction("cmp " + srcs[1] + ", " + srcs[0])
			elif len(srcs) == 1:
				print "cmp " + srcs[0] + ", 0"
				self.addInstruction("cmp " + src2[0] + ", 0")
		elif HANDLER_INDEX == 0xF:
			self.TMP_VAR_1, self.TMP_VAR_2 = None, None
			self.incVMEIP(1)
			while True:
				shift_type = self.getByte()
				if not shift_type:
					break
				if shift_type == 0x6:
					self.VIRTUAL_MACHINE_SHIFT_LEFT()
				elif shift_type == 0x7:
					self.VIRTUAL_MACHINE_SHIFT_RIGHT()
				else:
					self.VIRTUAL_MACHINE_EXECUTE_MATHOP(HANDLER_INDEX)
		elif HANDLER_INDEX == 0x10:
			self.TMP_VAR_1, self.TMP_VAR_2 = None, None
			self.incVMEIP(1)
			while True:
				shift_type = self.getByte()
				if not shift_type:
					break
				if shift_type == 0x6:
					self.VIRTUAL_MACHINE_SHIFT_LEFT()
				elif shift_type == 0x7:
					self.VIRTUAL_MACHINE_SHIFT_RIGHT()
				else:
					self.VIRTUAL_MACHINE_EXECUTE_MATHOP(HANDLER_INDEX)
		elif HANDLER_INDEX == 0x11:
			self.TMP_VAR_1, self.TMP_VAR_2 = None, None
			self.incVMEIP(1)
			while True:
				shift_type = self.getByte()
				if not shift_type:
					break
				if shift_type == 0x6:
					self.VIRTUAL_MACHINE_SHIFT_LEFT()
				elif shift_type == 0x7:
					self.VIRTUAL_MACHINE_SHIFT_RIGHT()
				else:
					self.VIRTUAL_MACHINE_EXECUTE_MATHOP(HANDLER_INDEX)
		elif HANDLER_INDEX == 0x12:
			self.incVMEIP(1)
			op_type = self.getByte()
			self.TMP_VAR_1, self.TMP_VAR_2 = -1, None
			if op_type:
				while True:
					self.VIRTUAL_MACHINE_EXECUTE_MATHOP(HANDLER_INDEX)
					if not self.getByte():
						break
		elif HANDLER_INDEX == 0x13:
			self.incVMEIP(1)
			op_type = self.getByte()
			self.TMP_VAR_1, self.TMP_VAR_2 = None, None
			if op_type:
				while True:
					self.VIRTUAL_MACHINE_EXECUTE_MATHOP(HANDLER_INDEX)
					if not self.getByte():
						break
		elif HANDLER_INDEX == 0x14:
			op_byte = self.getByte(1)
			self.TMP_VAR_1, self.TMP_VAR_2 = None, None
			self.incVMEIP(1)
			if op_byte == 0x2:
				index = self.getDword(1)
				reg = self.ARM_REGS[index]
				self.incVMEIP(5)
				self.TMP_VAR_1 = reg
				print "mov TMP_VAR_1, " + reg
				self.addInstruction("mov TMP_VAR_1, " + reg)
			elif op_byte == 0x1:
				imm = self.getDword(1)
				self.incVMEIP(5)
				self.TMP_VAR_1 = imm
				print "mov TMP_VAR_1, " + hex(imm)
				self.addInstruction("mov TMP_VAR_1, " + hex(imm))
			#else:
			#	self.incVMEIP(1)
			while True:
				op_byte = self.getByte()
				if not op_byte:
					break
				if op_byte == 0x6:
					self.VIRTUAL_MACHINE_SHIFT_LEFT()
				elif op_byte == 0x7:
					self.VIRTUAL_MACHINE_SHIFT_RIGHT()
				else:
					self.VIRTUAL_MACHINE_EXECUTE_MATHOP(HANDLER_INDEX)
		elif HANDLER_INDEX == 0x15:
			self.TMP_VAR_1, self.TMP_VAR_2 = None, None
			self.incVMEIP(1)
			val = self.getByte()
			if val:
				while True:
					self.VIRTUAL_MACHINE_MATHOPS(0x80, 0x81)
					if not self.getByte():
						break
		elif HANDLER_INDEX == 0x16:
			self.TMP_VAR_1, self.TMP_VAR_2 = None, None
			self.incVMEIP(1)
			val = self.getByte()
			if val:
				while True:
					self.VIRTUAL_MACHINE_MATHOPS(0x84, 0x85)
					if not self.getByte():
						break
		elif HANDLER_INDEX == 0x17:
			self.TMP_VAR_1, self.TMP_VAR_2 = None, None
			self.incVMEIP(1)
			val = self.getByte()
			if val:
				while True:
					self.VIRTUAL_MACHINE_MATHOPS(0x82, 0x83)
					if not self.getByte():
						break
		elif HANDLER_INDEX == 0x18:
			self.TMP_VAR_1, self.TMP_VAR_2 = None, None
			self.incVMEIP(1)
			val = self.getByte()
			if val:
				while True:
					self.VIRTUAL_MACHINE_MATHOPS(0x86, 0x87)
					if not self.getByte():
						break
		elif HANDLER_INDEX == 0x19:
			self.TMP_VAR_1, self.TMP_VAR_2 = None, None
			self.incVMEIP(1)
			val = self.getByte()
			if val:
				while True:
					self.VIRTUAL_MACHINE_MATHOPS(0x88, 0x89)
					if not self.getByte():
						break
		elif HANDLER_INDEX == 0x1D:
			# BLX <ADDR>
			flag = self.getByte(1)
			if not flag:
				self.incVMEIP(1)
				print "nop; blx not taken"
				self.addInstruction("nop; blx not taken")
			else:
				base = self.getDword(5)
				offset = self.getDword(1)
				self.incVMEIP(9)
				address = self.VM_REG_CTX["pc"] - offset + base
				sign = "+" if (base - offset) >= 0 else ""
				print "blx <lr" + sign + hex(base - offset) + "> ; address = " + hex(address)
				self.addInstruction("blx <lr" + sign + hex(base - offset) + "> ; address = " + hex(address))
		elif HANDLER_INDEX == 0x21:
			self.incVMEIP(1)
			op_byte = self.getByte()
			if not op_byte:
				return
			self.incVMEIP(1)
			index = self.getDword()
			reg = self.ARM_REGS[index]
			self.incVMEIP(4)
			print "blx " + reg# + "; args = R0, R1, R2, R3, reg = R0"
		elif HANDLER_INDEX == 0x23:
			self.incVMEIP(1)
			self.TMP_VAR_1, self.TMP_VAR_2 = None, None
			if self.getByte():
				while True:
					self.VIRTUAL_MACHINE_EXECUTE_MATHOP(HANDLER_INDEX)
					if not self.getByte():
						break
		elif HANDLER_INDEX in { 0x1E, 0x1F, 0x24, 0x25 }:
			# B<CC> -> conditional jump
			self.incVMEIP(1)
			LABEL_1, LABEL_2 = self.VIRTUAL_MACHINE_CONDITIONAL_JUMP(HANDLER_INDEX)
			if "LABEL_" + hex(LABEL_1) not in self.nodes and LABEL_1 not in self.unvisited and LABEL_1 != 0xFFFFFFFF:
				self.unvisited.append(LABEL_1)
			if "LABEL_" + hex(LABEL_2) not in self.nodes and LABEL_2 not in self.unvisited and LABEL_2 != 0xFFFFFFFF:
				self.unvisited.append(LABEL_2)
			# Add children to the current node
			self.addChild("LABEL_" + hex(LABEL_1))
			self.addChild("LABEL_" + hex(LABEL_2))
			# Check if we are jumping in the middle of a known node
			for label in [ LABEL_1, LABEL_2 ]:
				for node_label, node in self.nodes.items():
					addr = node.getStartAddress()
					if addr < label:
						for index, instruction in enumerate(node.insn):
							if instruction[0] == label:
								# Resize current node
								first_part = node.insn[:index]
								second_part = node.insn[index:]
								node.insn = first_part
								old_children = node.children
								node.children = []
								# Add second_part to a new node
								new_label = "LABEL_" + hex(label)
								new_node = Node(new_label)
								new_node.insn = second_part
								new_node.children = old_children
								# Add the new_node to the children of the node
								node.addChild(new_label)
								# Add new_node to the dictionary
								self.nodes.update({ new_label : new_node })
								break
			# Reset the VM_EIP
			self.VM_EIP = None
		elif HANDLER_INDEX == 0xE1:
			return False
		else:
			if len(self.unvisited) > 0:
				self.VM_EIP = self.unvisited.pop()
				self.currentNode = "LABEL_" + hex(self.VM_EIP)
				self.nodes.update({ self.currentNode : Node(self.currentNode) })
			else:
				print "[!] Unsupported handler: " + hex(HANDLER_INDEX)
				#quit()
				return False

		return True

	def isStopped(self):

		return self.VM_EIP > self.VM_BYTECODE_SIZE

	def printContext(self):
		for reg in self.ARM_REGS:
			print reg + " = " + hex(self.VM_REG_CTX[reg])

	def addInstruction(self, insn):
		node = self.nodes.get(self.currentNode)
		node.addInstruction(self.current_VM_EIP, insn)
		self.nodes.update({ self.currentNode : node })

	def addChild(self, label):
		node = self.nodes.get(self.currentNode)
		node.addChild(label)
		self.nodes.update({ self.currentNode : node })

	def drawGraph(self, name):
		graph = pydot.Dot(graph_type='digraph')
		# Add nodes
		graph_nodes = {}
		for label, node in self.nodes.items():
			pydotNode = node.getPydotNode()
			graph.add_node(pydotNode)
			graph_nodes.update({ label : pydotNode })
		# Add edges
		for label, node in self.nodes.items():
			for child in node.getChildren():
				node1, node2 = graph_nodes.get(label), graph_nodes.get(child)
				if node1 and node2:
					graph.add_edge(pydot.Edge(node1, node2))
		# Draw the graph
		graph.write_png(name)

if __name__ == "__main__":

	with open(sys.argv[1], "r") as bytecode:
		lines = bytecode.readlines()
		size = int(lines[0].split("=")[1], 16)
		bytecode = lines[1].split("=")[1].split(",")

		vm = VirtualMachine(bytecode, size)
		while vm.singleStep():
			raw_input()
			#pass
		vm.drawGraph(sys.argv[1].replace(".txt", ".png"))
