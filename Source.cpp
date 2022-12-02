#include <Windows.h>
#include <stdio.h>


int main(int argc, char* argv[])
{
	HANDLE hFileShellcode = INVALID_HANDLE_VALUE;
	HANDLE hFileOutput = INVALID_HANDLE_VALUE;
	DWORD dwRead, dwWritten;
	LARGE_INTEGER liFileSize;
	BOOL bSucceed;
	BOOL bX64;
	PVOID pShellcode = NULL;

	IMAGE_DOS_HEADER imageDosHeader = { 0 };
	IMAGE_NT_HEADERS64 imageNtHeaders64 = { 0 };
	IMAGE_NT_HEADERS32 imageNtHeaders32 = { 0 };
	IMAGE_SECTION_HEADER imageSectionHeader = { 0 };
	unsigned char text[8] = { ',', 't', 'e', 'x', 't', '\x00', '\x00', '\x00' };


	if (argc != 4)
	{
		printf(".\\%s <Shellcode.bin> <ExecutableOutput.exe> <arch>\n", argv[0]);
		printf("arch = x64 or x86\n");
		return 0;
	}
	if (strcmp(argv[3], "x64") == 0)
	{
		bX64 = TRUE;
	}
	else if (strcmp(argv[3], "x86") == 0)
	{
		bX64 = FALSE;
	}
	else
	{
		printf("Invalid architecture\n");
		return 0;
	}

	do
	{
		hFileShellcode = CreateFileA(argv[1], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFileShellcode == INVALID_HANDLE_VALUE)
		{
			printf("[*] Failed to open shellcode file %s\n", argv[1]);
			break;
		}

		if (!GetFileSizeEx(hFileShellcode, &liFileSize))
		{
			printf("[*] Failed to get shellcode size\n");
			break;
		}

		pShellcode = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, liFileSize.LowPart);
		if (!pShellcode)
		{
			printf("[*] Failed to allocate memory for shellcode\n");
			break;
		}

		if (!ReadFile(hFileShellcode, pShellcode, liFileSize.LowPart, &dwRead, NULL))
		{
			printf("[*] Failed to read shellcode\n");
			break;

		}

		printf("[*] Shellcode read - size %d\n", liFileSize.LowPart);

		printf("[*] Creating PE headers\n");

		printf("[*] ImageDosHeaders\n");
		imageDosHeader.e_magic = 0x5A4D;
		imageDosHeader.e_lfanew = sizeof(IMAGE_DOS_HEADER);

		if (bX64)
		{
			printf("[*] ImageNtHeaders64\n");

			// PE
			imageNtHeaders64.Signature = 0x00004550;

			printf("[*] ImageNtHeaders.FileHeaders\n");

			// AMD64 - TODO add support later
			imageNtHeaders64.FileHeader.Machine = 0x8664;

			// Only .text section
			imageNtHeaders64.FileHeader.NumberOfSections = 1;

			// File is executable, can handle more than 2g
			imageNtHeaders64.FileHeader.Characteristics = 0022;

			// Size of optional headers
			imageNtHeaders64.FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);

			printf("[*] ImageNtHeaders.OptionalHeader\n");

			// PE64
			imageNtHeaders64.OptionalHeader.Magic = 0x020B;

			// Address of entry - 0x1000 Virtual Address, first byte of .text section
			imageNtHeaders64.OptionalHeader.AddressOfEntryPoint = 0x1000;

			// Section alignment - default 0x1000, doesn't matter, it is after loaded to memory
			imageNtHeaders64.OptionalHeader.SectionAlignment = 0x1000;

			// File alignment, sadly 0x200 is the lowest
			imageNtHeaders64.OptionalHeader.FileAlignment = 0x200;

			// Some version shit needed
			imageNtHeaders64.OptionalHeader.MajorOperatingSystemVersion = 0x6;
			imageNtHeaders64.OptionalHeader.MinorOperatingSystemVersion = 0x0;
			imageNtHeaders64.OptionalHeader.MajorImageVersion = 0x0;
			imageNtHeaders64.OptionalHeader.MinorImageVersion = 0x0;
			imageNtHeaders64.OptionalHeader.MajorSubsystemVersion = 0x6;
			imageNtHeaders64.OptionalHeader.MinorSubsystemVersion = 0x0;

			// Calculate the shellcode size + 0x1000
			imageNtHeaders64.OptionalHeader.SizeOfImage = 0x1000 + liFileSize.LowPart;

			imageNtHeaders64.OptionalHeader.SizeOfHeaders = sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS64) + sizeof(IMAGE_SECTION_HEADER);

			// GUI
			imageNtHeaders64.OptionalHeader.Subsystem = 0x2;

			// DLL can move (ASLR) and more stuff
			imageNtHeaders64.OptionalHeader.DllCharacteristics = 0x8160;

		}
		else
		{
			printf("[*] ImageNtHeaders32\n");

			// PE
			imageNtHeaders32.Signature = 0x00004550;

			printf("[*] ImageNtHeaders.FileHeaders\n");

			// Intel386
			imageNtHeaders32.FileHeader.Machine = 0x014C;

			// Only .text section
			imageNtHeaders32.FileHeader.NumberOfSections = 1;

			// File is executable, can handle more than 2g
			imageNtHeaders32.FileHeader.Characteristics = 0022;

			// Size of optional headers
			imageNtHeaders32.FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER32);

			printf("[*] ImageNtHeaders.OptionalHeader\n");

			// PE32
			imageNtHeaders32.OptionalHeader.Magic = 0x010B;

			// Address of entry - 0x1000 Virtual Address, first byte of .text section
			imageNtHeaders32.OptionalHeader.AddressOfEntryPoint = 0x1000;

			// Section alignment - default 0x1000, doesn't matter, it is after loaded to memory
			imageNtHeaders32.OptionalHeader.SectionAlignment = 0x1000;

			// File alignment, sadly 0x200 is the lowest
			imageNtHeaders32.OptionalHeader.FileAlignment = 0x200;

			// Some version shit needed
			imageNtHeaders32.OptionalHeader.MajorOperatingSystemVersion = 0x6;
			imageNtHeaders32.OptionalHeader.MinorOperatingSystemVersion = 0x0;
			imageNtHeaders32.OptionalHeader.MajorImageVersion = 0x0;
			imageNtHeaders32.OptionalHeader.MinorImageVersion = 0x0;
			imageNtHeaders32.OptionalHeader.MajorSubsystemVersion = 0x6;
			imageNtHeaders32.OptionalHeader.MinorSubsystemVersion = 0x0;

			// Calculate the shellcode size + 0x1000
			imageNtHeaders32.OptionalHeader.SizeOfImage = 0x1000 + liFileSize.LowPart;

			imageNtHeaders32.OptionalHeader.SizeOfHeaders = sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS32) + sizeof(IMAGE_SECTION_HEADER);

			// GUI
			imageNtHeaders32.OptionalHeader.Subsystem = 0x2;

			// DLL can move (ASLR) and more stuff
			imageNtHeaders32.OptionalHeader.DllCharacteristics = 0x8540;

		}

		printf("[*] ImageSectionHeader\n");

		// Raw data size and VirtualSize is equals to shellcode size
		imageSectionHeader.SizeOfRawData = liFileSize.LowPart;
		imageSectionHeader.Misc.VirtualSize = liFileSize.LowPart;

		// Because of the SectionAlignment, doesn't matter, after loaded
		imageSectionHeader.VirtualAddress = 0x1000;

		// Because of FileAlignment, must be on 0x200, which is bigger that the header sizes combined.
		imageSectionHeader.PointerToRawData = 0x200;

		// Execute read and more stuff from CFF on the .text section
		imageSectionHeader.Characteristics = 0x60000020;

		// Write .text\x00 section name
		for (size_t i = 0; i < 8; i++)
		{
			imageSectionHeader.Name[i] = text[i];
		}

		printf("[*] Finished building file, now writing to output\n");

		hFileOutput = CreateFileA(argv[2], GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFileOutput == INVALID_HANDLE_VALUE)
		{
			printf("[*] Failed to open output file %s\n", argv[2]);
			break;
		}

		printf("[*] Writing headers\n");

		if (bX64)
		{
			// Write headers
			if (!WriteFile(hFileOutput, &imageDosHeader, sizeof(imageDosHeader), &dwWritten, NULL) ||
				!WriteFile(hFileOutput, &imageNtHeaders64, sizeof(imageNtHeaders64), &dwWritten, NULL) ||
				!WriteFile(hFileOutput, &imageSectionHeader, sizeof(imageSectionHeader), &dwWritten, NULL))
			{
				printf("[*] Failed to write headers to output file\n");
				break;
			}
		}
		else
		{
			// Write headers
			if (!WriteFile(hFileOutput, &imageDosHeader, sizeof(imageDosHeader), &dwWritten, NULL) ||
				!WriteFile(hFileOutput, &imageNtHeaders32, sizeof(imageNtHeaders32), &dwWritten, NULL) ||
				!WriteFile(hFileOutput, &imageSectionHeader, sizeof(imageSectionHeader), &dwWritten, NULL))
			{
				printf("[*] Failed to write headers to output file\n");
				break;
			}

		}

		printf("[*] Writing padding\n");

		if (bX64)
		{
			printf("[*] Writing padding\n");

			// Write padding until 0x200, file alignment
			bSucceed = true;
			for (size_t i = 0; i < 0x200 - sizeof(imageDosHeader) - sizeof(imageNtHeaders64) - sizeof(imageSectionHeader); i++)
			{
				char pad = '\x00';
				if (!WriteFile(hFileOutput, &pad, 1, &dwWritten, NULL))
				{
					bSucceed = false;
					break;
				}
			}
			if (!bSucceed)
			{
				printf("[*] Failed to write pad to output file\n");
				break;
			}
		}
		else
		{
			// Write padding until 0x200, file alignment
			bSucceed = true;
			for (size_t i = 0; i < 0x200 - sizeof(imageDosHeader) - sizeof(imageNtHeaders32) - sizeof(imageSectionHeader); i++)
			{
				char pad = '\x00';
				if (!WriteFile(hFileOutput, &pad, 1, &dwWritten, NULL))
				{
					bSucceed = false;
					break;
				}
			}
			if (!bSucceed)
			{
				printf("[*] Failed to write pad to output file\n");
				break;
			}
		}

		printf("[*] Writing shellcode\n");

		// Write shellcode to the .text section
		if (!WriteFile(hFileOutput, pShellcode, liFileSize.LowPart, &dwWritten, NULL))
		{
			printf("[*] Failed to write shellcode to output file\n");
			break;
		}


	} while (false);


	printf("[*] Cleanup\n");

	// Cleanup
	if (hFileShellcode != INVALID_HANDLE_VALUE)
	{
		CloseHandle(hFileShellcode);
	}

	if (hFileOutput != INVALID_HANDLE_VALUE)
	{
		CloseHandle(hFileOutput);
	}

	if (pShellcode)
	{
		HeapFree(GetProcessHeap(), 0, pShellcode);
	}



	return 0;

}




