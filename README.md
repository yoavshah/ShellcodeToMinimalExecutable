# ShellcodeToMinimalExecutable
A nice to have tool that rebuild a shellcode to a minimal executable

Usage:
		.\ShellcodeToMinimalExecutable <Shellcode.bin> <ExecutableOutput.exe> <x64 or x86>


Examples of x64 shellcode and x86 shellcode that pop up a messagebox in repo



This code just create those 3 headers one after another without paddings.
The reason why I had to put the shellcode after 0x200 was because of the minimal file alignment


IMAGE_DOS_HEADER

IMAGE_NT_HEADER

IMAGE_SECTION_HEADER

--------- 0x200 ----------

Shellcode
