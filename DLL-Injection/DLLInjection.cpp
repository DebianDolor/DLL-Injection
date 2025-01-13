#include "utils.h"
#include "DLLInjection.h"
#include <windows.h> 
#include <iostream>
#include <tlhelp32.h>
#include <ShlObj.h>

bool InjectDLL(DWORD processID, const char* dllPath) {
    //HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
    HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, processID);
    if (!hProcess) {
        std::wcerr << L"Failed to open process. Error: " << GetLastError() << std::endl;
        return false;
    }

    std::wcout << L"Target process ID: " << processID << std::endl;

    LPVOID pRemoteMemory = VirtualAllocEx(hProcess, NULL, strlen(dllPath) + 1, MEM_COMMIT, PAGE_READWRITE);
    if (!pRemoteMemory) {
        std::wcerr << L"Failed to allocate memory in target process. Error: " << GetLastError() << std::endl;
        CloseHandle(hProcess);
        return false;
    }

    if (!WriteProcessMemory(hProcess, pRemoteMemory, dllPath, strlen(dllPath) + 1, NULL)) {
        std::cerr << "Failed to write to target process memory. Error: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    LPVOID pLoadLibrary = (LPVOID)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA");
    if (!pLoadLibrary) {
        std::cerr << "Failed to get address of LoadLibraryA. Error: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibrary, pRemoteMemory, 0, NULL);
    if (!hThread) {
        std::wcerr << L"Failed to create remote thread. Error: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    WaitForSingleObject(hThread, INFINITE);

    VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProcess);

    std::cout << "DLL injected successfully." << std::endl;
    return true;
}

std::string GetDownloadsFolderPath() {
    PWSTR downloadsPath = NULL;
    HRESULT hr = SHGetKnownFolderPath(FOLDERID_Downloads, 0, NULL, &downloadsPath);
    if (SUCCEEDED(hr)) {
        std::wstring ws(downloadsPath);
        std::string downloadsFolder(ws.begin(), ws.end());
        CoTaskMemFree(downloadsPath);
        return downloadsFolder;
    }
    else {
        std::cerr << "Failed to get Downloads folder path. Error: " << hr << std::endl;
        return "";
    }
}

void DLLInjection() {
    const wchar_t* processName = L"notepad.exe";  // Name of the process to search for
    DWORD pid = GetProcessIdByName(processName);

    std::string downloadsFolderPath = GetDownloadsFolderPath();
    if (downloadsFolderPath.empty()) {
        std::cerr << "Could not retrieve the Downloads folder path." << std::endl;
        return;
    }

    std::string dllPath = "C:\\Users\\ethic\\Desktop\\Hacktivity\\Windows Exploit\\Resources\\injector.dll";

    if (InjectDLL(pid, dllPath.c_str())) {
        std::cout << "Injection successful!" << std::endl;
    }
    else {
        std::cout << "Injection failed." << std::endl;
    }

}