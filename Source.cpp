#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#ifdef INVALIDRVA
#undef INVALIDRVA
#endif
#define INVALIDRVA 0xffffffff
DWORD RVA2FA(WORD nrSections, IMAGE_SECTION_HEADER *pSec, DWORD RVA)
{
	for (int i = 0; i < nrSections; i++)
	{
		if (pSec->VirtualAddress <= RVA && pSec->Misc.VirtualSize + pSec->VirtualAddress > RVA)
		{
			return RVA - pSec->VirtualAddress + pSec->PointerToRawData;
		}
		pSec++;
	}
	return 0xffffffff;
}

int main(int argc, char** argv[])
{
	if (argc != 2)
	{
		printf("Incorrect number of arguments\n");
		return -1;
	}
	HANDLE file = CreateFileA((LPCSTR)argv[1], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (file == INVALID_HANDLE_VALUE)
	{
		printf("Couldn't open the file, error 0x%x", GetLastError());
		return -1;
	}
	LARGE_INTEGER fileSize;
	fileSize.HighPart = 0;
	BOOL returnSize = GetFileSizeEx(file, &fileSize);
	if (returnSize == 0 || fileSize.HighPart > 0)
	{
		printf("File is too big or couldn't get the size 0x%x", GetLastError());
		CloseHandle(file);
		return -1;
	}
	HANDLE hMap = CreateFileMappingA(file, NULL, PAGE_READONLY, 0, 0, NULL);
	if (hMap == NULL)
	{
		printf("Couldn't map the file, error 0x%x", GetLastError());
		CloseHandle(file);
		return -1;
	}
	char* buffer = (char*)malloc(fileSize.LowPart * sizeof(char));
	buffer = (char*)MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, fileSize.LowPart);
	if (buffer == NULL)
	{
		CloseHandle(file);
		CloseHandle(hMap);
		printf("Couldn't create a view");
		return -1;
	}
	CloseHandle(file);
	CloseHandle(hMap);
	if (0x3c > fileSize.LowPart)
	{
		UnmapViewOfFile(buffer);
		return -1;
	}
	int ntHeaderOffset;
	_IMAGE_DOS_HEADER dos_header = *(PIMAGE_DOS_HEADER)buffer;
	ntHeaderOffset = dos_header.e_lfanew;  //offset IMAGE_NT_HEADER;
	if (ntHeaderOffset > fileSize.LowPart)
	{
		UnmapViewOfFile(buffer);
		return -1;
	}
	_IMAGE_NT_HEADERS ntHeader = *(PIMAGE_NT_HEADERS)((BYTE*)buffer + ntHeaderOffset);
	printf("File Header: \n");
	if (ntHeaderOffset + 0x4 > fileSize.LowPart)
	{
		UnmapViewOfFile(buffer);
		return -1;
	}
	_IMAGE_FILE_HEADER fileHeader = *(PIMAGE_FILE_HEADER)((BYTE*)buffer + ntHeaderOffset + 0x4);
	printf("-Machine:");
	if (ntHeaderOffset + 0x6 > fileSize.LowPart)
	{
		UnmapViewOfFile(buffer);
		return -1;
	}
	printf("0x%x\n", fileHeader.Machine);
	if (ntHeaderOffset + 0x8 > fileSize.LowPart)
	{
		UnmapViewOfFile(buffer);
		return -1;
	}
	printf("-NumberOfSections:0x%x\n", fileHeader.NumberOfSections);
	if (ntHeaderOffset + 0x18 > fileSize.LowPart)
	{
		UnmapViewOfFile(buffer);
		return -1;
	}
	printf("-Characteristics:0x%x\n", fileHeader.Characteristics);

	_IMAGE_OPTIONAL_HEADER optionalHeader = *(PIMAGE_OPTIONAL_HEADER)((BYTE*)buffer + ntHeaderOffset + 0x18); //Optional Header
	int optionalHeaderOffset = ntHeaderOffset + 0x18;
	if (optionalHeaderOffset + 0x14 > fileSize.LowPart)
	{
		UnmapViewOfFile(buffer);
		return -1;
	}
	printf("Optional Header:\n");

	printf("-AdressOfEntryPoint:");
	printf("0x%x\n", optionalHeader.AddressOfEntryPoint);

	if (optionalHeaderOffset + 0x20 > fileSize.LowPart)
	{
		UnmapViewOfFile(buffer);
		return -1;
	}
	printf("-ImageBase: 0x%x\n", optionalHeader.ImageBase);

	if (optionalHeaderOffset + 0x24 > fileSize.LowPart)
	{
		UnmapViewOfFile(buffer);
		return -1;
	}
	printf("-SectionAllignmnet: 0x%x\n", optionalHeader.SectionAlignment);

	if (optionalHeaderOffset + 0x28 > fileSize.LowPart)
	{
		UnmapViewOfFile(buffer);
		return -1;
	}
	printf("-FileAlignment: 0x%x\n", optionalHeader.FileAlignment);
	
	if (optionalHeaderOffset + 0x46 > fileSize.LowPart)
	{
		UnmapViewOfFile(buffer);
		return -1;
	}
	printf("-Subsystem: 0x%x\n", optionalHeader.Subsystem);

	if (optionalHeaderOffset + 0x60 > fileSize.LowPart)
	{
		UnmapViewOfFile(buffer);
		return -1;
	}
	printf("-NumberOfRvaAndSizes: 0x%x\n", optionalHeader.NumberOfRvaAndSizes);


	printf("Sections:\n");
	int imageSectionOffset = ntHeaderOffset + 0x18 + 0x60 + 16 * 8;
	if (imageSectionOffset > fileSize.LowPart)
	{
		UnmapViewOfFile(buffer);
		return -1;
	}
	PIMAGE_SECTION_HEADER sections = (PIMAGE_SECTION_HEADER)((BYTE*)buffer + imageSectionOffset);
	for (int i = 0; i < fileHeader.NumberOfSections; i++)
	{
		if (imageSectionOffset + i * 0x24 + 8 > fileSize.LowPart)
		{
			UnmapViewOfFile(buffer);
			return -1;
		}
		for (int j = 0; j < 8; j++)
		{
			printf("%c", sections[i].Name[j]);
		}
		if (imageSectionOffset + i * 0x24 + 0x0c > fileSize.LowPart)
		{
			UnmapViewOfFile(buffer);
			return -1;
		}
		printf(", 0x%x", sections[i].Misc.PhysicalAddress);
		if (imageSectionOffset + i * 0x24 + 0x14 > fileSize.LowPart)
		{
			UnmapViewOfFile(buffer);
			return -1;
		}
		printf(", 0x%x", sections[i].SizeOfRawData);
		printf("\n");
	}

	int VirtualAddress1 = 0;
	int VirtualAddress2 = 0;
	if (optionalHeaderOffset + 0x64 > fileSize.LowPart || optionalHeaderOffset + 0x6B > fileSize.LowPart)
	{
		UnmapViewOfFile(buffer);
		return -1;
	}
	memcpy(&VirtualAddress1, &buffer[optionalHeaderOffset + 0x60], 4);
	memcpy(&VirtualAddress2, &buffer[optionalHeaderOffset + 0x68], 4);

	int RVAoffsetExports = VirtualAddress1;
	int RVAoffsetImports = VirtualAddress2;
	_IMAGE_SECTION_HEADER *pSec = (_IMAGE_SECTION_HEADER*)&(buffer[imageSectionOffset]);
	
	int offsetExports = RVA2FA(fileHeader.NumberOfSections, pSec, RVAoffsetExports);
	int offsetImports = RVA2FA(fileHeader.NumberOfSections, pSec, RVAoffsetImports);

	_IMAGE_EXPORT_DIRECTORY* pExpDir = NULL;
	_IMAGE_IMPORT_DESCRIPTOR* pImpDir = NULL;
	if (offsetExports != INVALIDRVA && offsetExports < fileSize.LowPart)
	{
		pExpDir = (_IMAGE_EXPORT_DIRECTORY*)((BYTE*)buffer + offsetExports);
	}
	if (offsetImports != INVALIDRVA && offsetImports < fileSize.LowPart)
	{
		pImpDir = (_IMAGE_IMPORT_DESCRIPTOR*)((BYTE*)buffer + offsetImports);
	}
	if (pExpDir != NULL)
	{
		if (offsetExports + 0x14 > fileSize.LowPart)  //numberOfFunctions
		{
			UnmapViewOfFile(buffer);
			return -1;
		}
		if (offsetExports + 0x18 > fileSize.LowPart)  //numberOfNames
		{
			UnmapViewOfFile(buffer);
			return -1;
		}

		if (offsetExports + 0x1c > fileSize.LowPart)  //AddressOfFunctions
		{
			UnmapViewOfFile(buffer);
			return -1;
		}
		if (offsetExports + 0x20 > fileSize.LowPart)  //AddressOfNames
		{
			UnmapViewOfFile(buffer);
			return -1;
		}

		if (offsetExports + 0x24 > fileSize.LowPart)  //AddressOfNameOrdinals
		{
			UnmapViewOfFile(buffer);
			return -1;
		}
	}
	
	printf("Exports:\n"); 
	if (pExpDir != NULL)
	{
		int physAddressFunctions = RVA2FA(fileHeader.NumberOfSections, pSec, pExpDir->AddressOfFunctions);
		int physAddressNameOrdinals = RVA2FA(fileHeader.NumberOfSections, pSec, pExpDir->AddressOfNameOrdinals);
		int physAddressNames = RVA2FA(fileHeader.NumberOfSections, pSec, pExpDir->AddressOfNames);
		if (physAddressFunctions == INVALIDRVA || physAddressNameOrdinals == INVALIDRVA || physAddressNames == INVALIDRVA)
		{
			printf("undef\n");
			UnmapViewOfFile(buffer);
			return -1;
		}
		if (physAddressFunctions > fileSize.LowPart || physAddressNameOrdinals > fileSize.LowPart || physAddressNames > fileSize.LowPart)
		{
			UnmapViewOfFile(buffer);
			return -1;
		}
		DWORD* func_table = (DWORD*)((BYTE*)buffer + RVA2FA(fileHeader.NumberOfSections, pSec, pExpDir->AddressOfFunctions)); //Get an array of pointers to the functions
		WORD* ord_table = (WORD*)((BYTE*)buffer + RVA2FA(fileHeader.NumberOfSections, pSec, pExpDir->AddressOfNameOrdinals)); //Get an array of ordinals
		DWORD* name_table = (DWORD*)((BYTE*)buffer + RVA2FA(fileHeader.NumberOfSections, pSec, pExpDir->AddressOfNames)); //Get an array of function names
		for (int i = 0; i < pExpDir->NumberOfNames; i++) //Exported functions by name
		{
			if (RVA2FA(fileHeader.NumberOfSections, pSec, name_table[i]) == INVALIDRVA)
			{
				printf("undef ");
			}
			if ((fileHeader.NumberOfSections, pSec, name_table[i]) < fileSize.LowPart)
			{
				if ((BYTE*)buffer + RVA2FA(fileHeader.NumberOfSections, pSec, name_table[i]) != NULL)  //is exported by name
				{
					printf("%s, ", (BYTE*)buffer + RVA2FA(fileHeader.NumberOfSections, pSec, name_table[i])); //print the name of each function iterated
					printf("0x%x, ", ord_table[i]);   //print the ordinal
					if (func_table[ord_table[i]] < optionalHeader.DataDirectory[0].VirtualAddress ||
						func_table[ord_table[i]] > optionalHeader.DataDirectory[0].VirtualAddress +
						optionalHeader.DataDirectory[0].Size)
					{
						printf("0x%x\n", func_table[ord_table[i]]);
					}
					else
					{
						if (RVA2FA(fileHeader.NumberOfSections, pSec, func_table[ord_table[i]]) == INVALIDRVA)
						{
							printf("undef\n");
						}
						else
						{
							printf("0x%x\n", RVA2FA(fileHeader.NumberOfSections, pSec, func_table[ord_table[i]]));
						}

					}//print the file address
				}
			}
		}
		for (int i = 0; i < pExpDir->NumberOfFunctions; i++)   //it's exported by ordinal
		{
			int j;
			for (j = 0; j < pExpDir->NumberOfNames; j++)
			{
				if (func_table[ord_table[j]] == func_table[i])
				{
					break;
				}
			}
			if (j >= pExpDir->NumberOfNames)
			{
				if (&func_table[i] > (DWORD*)((BYTE*) buffer + fileSize.LowPart))
				{
					break;
				}
				if (func_table[i] < pSec->VirtualAddress || func_table[i] > pSec->Misc.VirtualSize + pSec->VirtualAddress)
				{
					printf(" , 0x%x, 0x%x\n", i - pExpDir->Base + 1, func_table[i]);
				}
				else
				{
					printf(" , 0x%x, 0x%x\n", i - pExpDir->Base + 1, (BYTE*)buffer + pSec->PointerToRawData + func_table[i] - pSec->VirtualAddress);
				}
			}
		}
	
	}
	
	printf("Imports:\n");
	if (pImpDir != NULL)
	{
		while (pImpDir->Characteristics != 0)
		{
			if (RVA2FA(fileHeader.NumberOfSections, pSec, pImpDir->OriginalFirstThunk) == INVALIDRVA)
			{
				printf("undef\n");
			}
			else
			{
				if (RVA2FA(fileHeader.NumberOfSections, pSec, pImpDir->OriginalFirstThunk) < fileSize.LowPart)
				{
					PIMAGE_THUNK_DATA pThunkData = (PIMAGE_THUNK_DATA)((BYTE*)buffer + RVA2FA(fileHeader.NumberOfSections, pSec, pImpDir->OriginalFirstThunk));
					while (pThunkData->u1.AddressOfData != 0)
					{
						if (RVA2FA(fileHeader.NumberOfSections, pSec, pImpDir->Name) == INVALIDRVA)
						{
							printf("undef, ");
						}
						else if (RVA2FA(fileHeader.NumberOfSections, pSec, pImpDir->Name) < fileSize.LowPart)
						{
							printf("%s, ", (BYTE*)buffer + RVA2FA(fileHeader.NumberOfSections, pSec, pImpDir->Name));
						}
						if (!(pThunkData->u1.AddressOfData & IMAGE_ORDINAL_FLAG))
						{
							if (RVA2FA(fileHeader.NumberOfSections, pSec, pThunkData[0].u1.AddressOfData) == INVALIDRVA)
							{
								printf("undef\n");
								pThunkData++;
								continue;
							}
							if (RVA2FA(fileHeader.NumberOfSections, pSec, pThunkData[0].u1.AddressOfData) < fileSize.LowPart)
							{
								PIMAGE_IMPORT_BY_NAME nameFunction = (PIMAGE_IMPORT_BY_NAME)((BYTE*)buffer + RVA2FA(fileHeader.NumberOfSections, pSec, pThunkData[0].u1.AddressOfData));
								printf("%s\n", nameFunction->Name);
							}
						}
						if ((pThunkData->u1.Ordinal & IMAGE_ORDINAL_FLAG))
						{
							printf("0x%x\n", pThunkData->u1.Ordinal);
						}
						pThunkData++;
					}
				}
			}
			pImpDir++;
		}
	}




	UnmapViewOfFile(buffer);
	system("pause");

	return 0;
}