# butterfly - Pwnable 150
Description:
```
Sometimes the universe smiles upon you. And sometimes, well, you just have to roll your sleeves up and do things yourself. Running at butterfly.pwning.xxx:9999 

Notes: The binary has been updated. Please download again if you have the old version. The only difference is that the new version (that's running on the server) has added setbuf(stdout, NULL); line.
```

They gave us a 64-bit [binary](PlaidCTF 2016/butterfly) running at butterfly.pwning.xxx:9999.

The binary seemed to do all its logic in the main function.  Here is the hexrays pseudocode:
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  signed int v3; // er14@1
  __int64 v4; // rax@2
  char v5; // bl@2
  __int64 v6; // rbp@2
  unsigned __int64 v7; // r15@2
  __int64 v8; // rax@5
  char v10; // [sp+0h] [bp-68h]@1
  __int64 v11; // [sp+40h] [bp-28h]@1

  v11 = *MK_FP(__FS__, 40LL);
  setbuf(_bss_start, 0LL);
  puts("THOU ART GOD, WHITHER CASTEST THY COSMIC RAY?");
  v3 = 1;
  if ( fgets(&v10, 50, stdin) )
  {
    v4 = strtol(&v10, 0LL, 0);
    v5 = v4;
    v6 = v4 >> 3;
    v7 = (v4 >> 3) & 0xFFFFFFFFFFFFF000LL;
    if ( mprotect((void *)v7, 0x1000uLL, 7) )
    {
      perror("mprotect1");
    }
    else
    {
      v3 = 1;
      *(_BYTE *)v6 ^= 1 << (v5 & 7);
      if ( mprotect((void *)v7, 0x1000uLL, 5) )
      {
        perror("mprotect2");
      }
      else
      {
        puts("WAS IT WORTH IT???");
        v3 = 0;
      }
    }
  }
  v8 = *MK_FP(__FS__, 40LL);
  if ( *MK_FP(__FS__, 40LL) == v11 )
    LODWORD(v8) = v3;
  return v8;
}
```

It calls sets RWX permissions and then RW permissions on an address from our input.
The function takes our given address, ANDs it with 0xFFFFFFFFFFFFF000 and calls mprotect on it for 0x1000 bytes. 
We can use this to write and execute our shellcode later.

The function also writes to a byte at an address by XORing itself with a mulitple of 2 up to 2**7
This power is chosen by the value of our given address' 3 least significant bits.

This value could range from 0x000 to 0x111.  For example, a 6 would perform a 1<<6 and a 2 would perform a 1<<2.

The chosen modified address is the given address shifted right by 3 bits.
So, to modify a byte to your desired value, you need to find what bits you need to XOR the original with.
If you need to XOR the original with something like 0b01011010, you would send 
```
original = original ^ (1<<1)
original = original ^ (1<<1)
original = original ^ (1<<1)
```




