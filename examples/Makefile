all: 01_access 02_gets 03_rwx_mem 04_memcpy 04_strncpy 04_strcpy 05_security_file_open 06_sprintf 07_snprintf 08_printf_mutability 09_system_mutability 10_system_abs 11_filep_unlocked 12_fixed_mmap 13_interceptable_path

clean:
	rm 01_access 02_gets 03_rwx_mem 04_memcpy 04_strncpy 04_strcpy 05_security_file_open 06_sprintf 07_snprintf 08_printf_mutability 09_system_mutability 10_system_abs 11_filep_unlocked 12_fixed_mmap 13_interceptable_path

01_access: 01_access.c
	gcc $(OPTION) 01_access.c -o 01_access

02_gets: 02_gets.c
	gcc $(OPTION) 02_gets.c -o 02_gets

03_rwx_mem: 03_rwx_mem.c
	gcc $(OPTION) 03_rwx_mem.c -o 03_rwx_mem

04_memcpy: 04_memcpy.c
	gcc $(OPTION) 04_memcpy.c -o 04_memcpy

04_strncpy: 04_strncpy.c
	gcc $(OPTION) 04_strncpy.c -o 04_strncpy

04_strcpy: 04_strcpy.c
	gcc $(OPTION) 04_strcpy.c -o 04_strcpy

05_security_file_open: 05_security_file_open.c
	gcc $(OPTION) 05_security_file_open.c -o 05_security_file_open

06_sprintf: 06_sprintf.c
	gcc $(OPTION) 06_sprintf.c -o 06_sprintf

07_snprintf: 07_snprintf.c
	gcc $(OPTION) 07_snprintf.c -o 07_snprintf

08_printf_mutability: 08_printf_mutability.c
	gcc $(OPTION) 08_printf_mutability.c -o 08_printf_mutability

09_system_mutability: 09_system_mutability.c
	gcc $(OPTION) 09_system_mutability.c -o 09_system_mutability

10_system_abs: 10_system_abs.c
	gcc $(OPTION) 10_system_abs.c -o 10_system_abs

11_filep_unlocked: 11_filep_unlocked.c
	gcc $(OPTION) 11_filep_unlocked.c -o 11_filep_unlocked

12_fixed_mmap: 12_fixed_mmap.c
	gcc $(OPTION) 12_fixed_mmap.c -o 12_fixed_mmap

13_interceptable_path: 13_interceptable_path.c
	gcc $(OPTION) 13_interceptable_path.c -o 13_interceptable_path