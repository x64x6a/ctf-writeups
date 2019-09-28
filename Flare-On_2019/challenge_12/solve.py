"""
kd> !analyze -v
*******************************************************************************
*                                                                             *
*                        Bugcheck Analysis                                    *
*                                                                             *
*******************************************************************************
SYSTEM_THREAD_EXCEPTION_NOT_HANDLED (7e)
This is a very common bugcheck.  Usually the exception address pinpoints
the driver/function that caused the problem.  Always note this address
as well as the link date of the driver/image that contains this address.
Arguments:
Arg1: ffffffffc0000005, The exception code that was not handled
Arg2: fffffa8003f9c621, The address that the exception occurred at
Arg3: fffff88007c6b958, Exception Record Address
Arg4: fffff88007c6b1b0, Context Record Address
Debugging Details:
------------------

KEY_VALUES_STRING: 1
    Key  : AV.Fault
    Value: Read
    Key  : Analysis.CPU.Sec
    Value: 1
    Key  : Analysis.Elapsed.Sec
    Value: 1
    Key  : Analysis.Memory.CommitPeak.Mb
    Value: 64

PROCESSES_ANALYSIS: 1
SERVICE_ANALYSIS: 1
STACKHASH_ANALYSIS: 1
TIMELINE_ANALYSIS: 1

DUMP_CLASS: 1
DUMP_QUALIFIER: 402
BUILD_VERSION_STRING:  7601.18741.amd64fre.win7sp1_gdr.150202-1526
SYSTEM_MANUFACTURER:  VMware, Inc.
VIRTUAL_MACHINE:  VMware
SYSTEM_PRODUCT_NAME:  VMware Virtual Platform
SYSTEM_VERSION:  None
BIOS_VENDOR:  Phoenix Technologies LTD
BIOS_VERSION:  6.00
BIOS_DATE:  04/13/2018
BASEBOARD_MANUFACTURER:  Intel Corporation
BASEBOARD_PRODUCT:  440BX Desktop Reference Platform
BASEBOARD_VERSION:  None
DUMP_TYPE:  0
BUGCHECK_P1: ffffffffc0000005
BUGCHECK_P2: fffffa8003f9c621
BUGCHECK_P3: fffff88007c6b958
BUGCHECK_P4: fffff88007c6b1b0
EXCEPTION_CODE: (NTSTATUS) 0xc0000005 - The instruction at 0x%p referenced memory at 0x%p. The memory could not be %s.
FAULTING_IP: 
+0
fffffa80`03f9c621 64a10000000050648925 mov eax,dword ptr fs:[2589645000000000h]
EXCEPTION_RECORD:  fffff88007c6b958 -- (.exr 0xfffff88007c6b958)
ExceptionAddress: fffffa8003f9c621
   ExceptionCode: c0000005 (Access violation)
  ExceptionFlags: 00000000
NumberParameters: 2
   Parameter[0]: 0000000000000000
   Parameter[1]: ffffffffffffffff
Attempt to read from address ffffffffffffffff
CONTEXT:  fffff88007c6b1b0 -- (.cxr 0xfffff88007c6b1b0)
rax=fffffa8003f9c610 rbx=fffffa80040c65c0 rcx=fffffa80036ab5c0
rdx=fffff880033c8138 rsi=fffffa80018cc090 rdi=0000000000000001
rip=fffffa8003f9c621 rsp=fffff88007c6bb98 rbp=0000000007c6bbb0
 r8=fffff80002c3f400  r9=0000000000000000 r10=0000000000000000
r11=fffff80002c3ae80 r12=fffffa80036ab5c0 r13=fffff880033bdcc0
r14=0000000000000000 r15=fffff80000b94080
iopl=0         nv up ei ng nz na po nc
cs=0010  ss=0018  ds=002b  es=002b  fs=0053  gs=002b             efl=00010286
fffffa80`03f9c621 64a10000000050648925 mov eax,dword ptr fs:[2589645000000000h] fs:0053:25896450`00000000=????????
Resetting default scope
CPU_COUNT: 1
CPU_MHZ: e75
CPU_VENDOR:  GenuineIntel
CPU_FAMILY: 6
CPU_MODEL: 9e
CPU_STEPPING: a
CPU_MICROCODE: 6,9e,a,0 (F,M,S,R)  SIG: 96'00000000 (cache) 96'00000000 (init)
DEFAULT_BUCKET_ID:  WIN7_DRIVER_FAULT
PROCESS_NAME:  System
CURRENT_IRQL:  2
FOLLOWUP_IP: 
man+1ce7
fffff880`033bdce7 89442428        mov     dword ptr [rsp+28h],eax
BUGCHECK_STR:  0x7E
READ_ADDRESS:  ffffffffffffffff 
ERROR_CODE: (NTSTATUS) 0xc0000005 - The instruction at 0x%p referenced memory at 0x%p. The memory could not be %s.
EXCEPTION_CODE_STR:  c0000005
EXCEPTION_PARAMETER1:  0000000000000000
EXCEPTION_PARAMETER2:  ffffffffffffffff
ANALYSIS_SESSION_HOST:  COMPUTERNAME
ANALYSIS_SESSION_TIME:  08-23-2019 23:07:56.0112
ANALYSIS_VERSION: 10.0.18914.1001 amd64fre
LAST_CONTROL_TRANSFER:  from 000000000001093a to fffffa8003f9c621
STACK_TEXT:  
fffff880`07c6bb98 00000000`0001093a : 00000000`00010ba8 ffffffff`ffffffff 00000000`00000080 fffff880`033bdce7 : 0xfffffa80`03f9c621
fffff880`07c6bba0 00000000`00010ba8 : ffffffff`ffffffff 00000000`00000080 fffff880`033bdce7 00000000`00000000 : 0x1093a
fffff880`07c6bba8 ffffffff`ffffffff : 00000000`00000080 fffff880`033bdce7 00000000`00000000 00000000`00000000 : 0x10ba8
fffff880`07c6bbb0 00000000`00000080 : fffff880`033bdce7 00000000`00000000 00000000`00000000 00000000`00000000 : 0xffffffff`ffffffff
fffff880`07c6bbb8 fffff880`033bdce7 : 00000000`00000000 00000000`00000000 00000000`00000000 00000000`00000000 : 0x80
fffff880`07c6bbc0 00000000`00000000 : 00000000`00000000 00000000`00000000 00000000`00000000 fffffa80`03f9c610 : man+0x1ce7

THREAD_SHA1_HASH_MOD_FUNC:  8175e3c8753aeb1696959f72ede260ebf3ea14c5
THREAD_SHA1_HASH_MOD_FUNC_OFFSET:  7c2abaddc43a7edcac2d2576e24447b109c16c2f
THREAD_SHA1_HASH_MOD:  8175e3c8753aeb1696959f72ede260ebf3ea14c5
FAULT_INSTR_CODE:  28244489
SYMBOL_STACK_INDEX:  5
SYMBOL_NAME:  man+1ce7
FOLLOWUP_NAME:  MachineOwner
MODULE_NAME: man
IMAGE_NAME:  man.sys
DEBUG_FLR_IMAGE_TIMESTAMP:  0
STACK_COMMAND:  .cxr 0xfffff88007c6b1b0 ; kb
FAILURE_BUCKET_ID:  X64_0x7E_man+1ce7
BUCKET_ID:  X64_0x7E_man+1ce7
PRIMARY_PROBLEM_CLASS:  X64_0x7E_man+1ce7
TARGET_TIME:  2019-08-02T14:38:33.000Z
OSBUILD:  7601
OSSERVICEPACK:  1000
SERVICEPACK_NUMBER: 0
OS_REVISION: 0
SUITE_MASK:  784
PRODUCT_TYPE:  1
OSPLATFORM_TYPE:  x64
OSNAME:  Windows 7
OSEDITION:  Windows 7 WinNt (Service Pack 1) TerminalServer SingleUserTS Personal
OS_LOCALE:  
USER_LCID:  0
OSBUILD_TIMESTAMP:  2015-02-02 18:25:01
BUILDDATESTAMP_STR:  150202-1526
BUILDLAB_STR:  win7sp1_gdr
BUILDOSVER_STR:  6.1.7601.18741.amd64fre.win7sp1_gdr.150202-1526
ANALYSIS_SESSION_ELAPSED_TIME:  4b6
ANALYSIS_SOURCE:  KM
FAILURE_ID_HASH_STRING:  km:x64_0x7e_man+1ce7
FAILURE_ID_HASH:  {ceed7a1b-a47b-c452-63c1-012e444d5204}
Followup:     MachineOwner
---------


kd> lmvm man
Browse full module list
start             end                 module name
fffff880`033bc000 fffff880`033cb000   man      T (no symbols)           
    Loaded symbol image file: man.sys
    Image path: \??\C:\Users\FLARE ON 2019\Desktop\man.sys
    Image name: man.sys
    Browse all global symbols  functions  data
    Timestamp:        unavailable (FFFFFFFE)
    CheckSum:         missing
    ImageSize:        0000F000
    Translations:     0000.04b0 0000.04e4 0409.04b0 0409.04e4
    Information from resource tables:

kd> .writemem C:\tmp\man.sys fffff880`033bc000 L?0000f000
Writing f000 bytes..............................



delete contents before 0x7110
    - start should've been 0xfffff880033bc000 + 0x7110  ??


"""



"""
# patch read

patching offset 0x1f7E:
74 27 -> 74 35
patching offset 0x1f7B:
83 F8 FF  -> 83 F8 00

# always jmp, dont verify size
patching offset 0x250A:
74 05 -> EB 06

# patch create file string to read from C:\FLID

patching offset 0x04C8
"\\.\%s" -> "C:\%s"
5C 5C 2E 5C 25 73 00 -> 43 3A 5C 25 73 00




$ grep "2019-08-02 14:24:" *
pslist.txt:0xfffffa800243bb30 cmd.exe                3248   1124      1       21      1      0 2019-08-02 14:24:04 UTC+0000                                 
pslist.txt:0xfffffa8003dd3060 conhost.exe            3488    360      2       51      1      0 2019-08-02 14:24:04 UTC+0000                                 
pstree.txt:. 0xfffffa8003dd3060:conhost.exe                     3488    360      2     51 2019-08-02 14:24:04 UTC+0000
pstree.txt:. 0xfffffa800243bb30:cmd.exe                         3248   1124      1     21 2019-08-02 14:24:04 UTC+0000
symlinkscan.txt:0x0000000030a45130      1      0 2019-08-02 14:24:28 UTC+0000   FLND                 \Device\FLND                                                



offset 5CA681b0
The flag
54 68 65 20 66 6C 61 67 00


offset 0F65f420
found this in memory searching for unicode "flare-on.com"
h.3._.b.r.3.4.d.c.r.u.m.b.s.@.f.l.a.r.e.-.o.n...c.o.m

h3_br34dcrumbs@flare-on.com
ultrium-hh3_br34dcrumbs@flare-on.com


git clone https://github.com/cube0x8/chrome_ragamuffin.git
git clone https://github.com/superponible/volatility-plugins.git
"""

"""
nonic
h3_br34dcrumbs@flare-on.com


FLARE_Loaded
"""



"""
# IDA python to fixup.. set offset to 0xFFFFF880033BC000

def find_code(addr, end):
    cc_count = 0
    in_cc = False
    while addr < end:
        b = Byte(addr)
        if b == 0xcc:
            cc_count += 1
            if cc_count >= 4:
                in_cc = True
        else:
            cc_count = 0
            if in_cc:
                in_cc = False
                #MakeCode(addr)
                MakeFunction(addr)
        addr += 1

find_code(0xFFFFF880033BC000+0x1010, 0xFFFFF880033C0608+0x1010)
find_code(0xFFFFF880033C072A+0x1010, 0xFFFFF880033C0BA1+0x1010)


find_code(0xFFFFF880033BD031, 0xFFFFF880033C1624)
find_code(0xFFFFF880033BD031, 0xFFFFF880033BD031+10)
find_code(0xFFFFF880033C1760, 0xFFFFF880033C1624)

# get a stack variable


def get_var(ea):
s = ''
for i in range(begin, end):
   s += chr(idc.get_operand_value(get_screen_ea(), 1))
print s




.writemem C:\tmp\stack.data fffff88007c6bba8 L?0000f000
"""


"""
lets recover the stack variables via hexdump of help.dmp...
FLARE_Loaded:
    rsp+0x5E0
    39ea7760
FLAR pool pointer:
    rsp+0x60
    39ea71e0 --> 0xfffffa8003f9c100


.writemem C:\tmp\flar.data fffffa8003f9c100 L?0000f000
 - assuming its 0xf000


looks like another driver
looks to just do a memcpy and call a pool


ret address for thread crash:  fffffa80`03f9c610 => 10c6f90380faffff



ZwAllocateVirtualMemory:
    rsp+0x48
    2EEFF750        2EEFF750 + A0 = 2eeff7f0
FLAR pool pointer:
    rsp+0xE8
    2eeff7f0 --> fffffa80020ad980

.writemem C:\tmp\flar2.data fffffa80020ad980 L?0000f000

odd string.. 

i.c.e.\.H.a.r.d.d.i.s.k.V.o.l.u.m.e.1.\.W.i.n.d.o.w.s.\.e.x.p.l.o.r.e.r...e.x.e

"""

"""
decided to guess `follow_th3_br34dcrumbs@flare-on.com`
...
solved..
"""