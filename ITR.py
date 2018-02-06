import lief

if __name__ == "__main__":

	library  = lief.parse("libjiagu.so")

	print "[+] ELF Header"
	print library.header

	print "[+] Initialization and Termination Routines"
	INIT_ENTRIES = [
		lief.ELF.DYNAMIC_TAGS.INIT, lief.ELF.DYNAMIC_TAGS.INIT_ARRAY, lief.ELF.DYNAMIC_TAGS.INIT_ARRAYSZ,	# .init_array
		lief.ELF.DYNAMIC_TAGS.PREINIT_ARRAY, lief.ELF.DYNAMIC_TAGS.PREINIT_ARRAYSZ,				# .preinit_array
		lief.ELF.DYNAMIC_TAGS.FINI, lief.ELF.DYNAMIC_TAGS.FINI_ARRAY, lief.ELF.DYNAMIC_TAGS.FINI_ARRAYSZ	# .fini_array
	]
	for entry in library.dynamic_entries:
		if entry.tag in INIT_ENTRIES:
			print entry
