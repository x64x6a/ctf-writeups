# The Cobol Job
```
https://www.imdb.com/title/tt5295894/ Update: The "sketchy code" mentioned in a comment is not relevant to the solution.

Director: panda
Cast: kylar, nneonneo
Genre: spwnable

Episodes
1 Cold Open   130 points
    cobol.pwni.ng 3083
```

---

## Overview

Our solution to this challenge can be broken up into three steps:
* Obtaining libc base from `/proc/self/maps`
* Copy a file to trigger use-after-free to overwrite tcache entry with `free_hook`
* Write one_gadget to `free_hook` and trigger a free to obtain a system shell

---

## Libc leak

We can leak segment mappings by reading from `/proc/self/maps`, however, we are not able to read directly from the file as it will trigger a `O_RDWR` and fail.  We can instead copy the `/proc/self/maps` file to `/dev/stdout` to read the segment mapping.

```python
do_copy("/proc/self/maps", "/dev/stdout")
```

---

## Trigger UAF

We eventually found a use-after-free vulnerability in `libcob` inside the copy file function, `CBL_COPY_FILE()`.  On line 4691, it retrieves an allocation from `cob_str_from_fld()`. On line 4698, the address is passed to `free()`. Then on line 4710, it triggers the UAF by reading the source file's contents into it.

```c
fn1 = cob_str_from_fld (cob_current_module->cob_procedure_parameters[0]);
...
free (fn1);
...
while ((i = read (fd1, fn1, sizeof(fn1))) > 0) {
...
}
```

Source reference: https://github.com/cooljeanius/open-cobol/blob/6391bcc51b26672d482e768cafc69d16a12036d5/libcob/fileio.c#L4710
<details>
  <summary>CBL_COPY_FILE() function</summary>

```c
int
CBL_COPY_FILE (unsigned char *fname1, unsigned char *fname2)
{
	char	*fn1;
	char	*fn2;
#ifdef	O_BINARY
	int	flag = O_BINARY;
#else
	int	flag = 0;
#endif
	int	ret;
	int	i;
	int	fd1, fd2;

	COB_CHK_PARMS (CBL_COPY_FILE, 2);

	if (!cob_current_module->cob_procedure_parameters[0]) {
		return -1;
	}
	if (!cob_current_module->cob_procedure_parameters[1]) {
		return -1;
	}
	fn1 = cob_str_from_fld (cob_current_module->cob_procedure_parameters[0]);
	flag |= O_RDONLY;
	fd1 = open (fn1, flag, 0);
	if (fd1 < 0) {
		free (fn1);
		return -1;
	}
	free (fn1);
	fn2 = cob_str_from_fld (cob_current_module->cob_procedure_parameters[1]);
	flag &= ~O_RDONLY;
	flag |= O_CREAT | O_TRUNC | O_WRONLY;
	fd2 = open (fn2, flag, 0660);
	if (fd2 < 0) {
		close (fd1);
		free (fn2);
		return -1;
	}
	free (fn2);
	ret = 0;
	while ((i = read (fd1, fn1, sizeof(fn1))) > 0) {
		if (write (fd2, fn1, (size_t)i) < 0) {
			ret = -1;
			break;
		}
	}
	close (fd1);
	close (fd2);
	return ret;
}
```

</details>

---

## Modifying Tcache

The freed value above will be pushed into a tcachebin if it that tcachebin is not full.  We can control which tcachebin here through the size of the source filename, as the same buffer for the source's filename is also used for the source's contents.  We give a filename of length 0x30 so we use the 0x40 size tcachebin.

To utilized this, we created and opened a file with a filename size of 0x30 (0x40 bin) with some arbitrary file size that differs.  We then wrote the address of `free_hook` into the file such that it would overwrite both of the freed memory's forward and back pointers.  We then copy this file with a new file with differing name size.  This will allocate the first filename, load it into the 0x40 tcache by freeing it, and then set the `free_hook` address as its forward and back pointers.  This will manipulate the tcache 0x40 bin such that the 2nd 0x40 allocation request will return the address to `free_hook`.

The 0x40 tcachebin will now look something like this:
```c
0x40 [  3]: 0x559497863700 —▸ 0x7f994e3368d8 (__free_hook-16) —▸ 0x7f994e9fd340 ◂— 0x7f994e9fd340
```

We then created and opened a new file with some other filename length and a file size of 0x38 for the 0x40 bin.  The create will pop off the 1st 0x40 entry and the open will pop off the 2nd 0x40 entry, `free_hook`, into a data buffer.  We then write into this buffer by writing the magic one_gadget to the open file.  We then close this file to trigger a call to `free()` and in turn jumping to our one_gadget value in `free_hook`.  We ran `/freader` to obtain the flag.

```
[+] Opening connection to cobol.pwni.ng on port 3083: Done
elf_base: 0x560792499000
heap_base: 0x5607945f9000
libc_base: 0x7f3a5e452000
Run `/freader` for flag
[*] Switching to interactive mode
$ /freader
PCTF{l3arning_n3w_languag3_sh0uld_start_with_g00d_bugs_99d4ec917d097f63107e}
```

---
