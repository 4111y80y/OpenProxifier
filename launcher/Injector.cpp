#include "Injector.h"
#include <psapi.h>
#include <vector>

Injector::InjectResult Injector::LaunchAndInject(
    const std::wstring& exePath,
    const std::wstring& dllPath,
    const std::wstring& commandLine,
    const ProxyConfig& config)
{
    InjectResult result;

    // Prepare command line (must be writable)
    std::wstring cmdLine = L"\"" + exePath + L"\"";
    if (!commandLine.empty()) {
        cmdLine += L" " + commandLine;
    }

    // Create process in suspended state
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };

    std::vector<wchar_t> cmdLineBuffer(cmdLine.begin(), cmdLine.end());
    cmdLineBuffer.push_back(L'\0');

    BOOL created = CreateProcessW(
        exePath.c_str(),
        cmdLineBuffer.data(),
        NULL,
        NULL,
        FALSE,
        CREATE_SUSPENDED,
        NULL,
        NULL,
        &si,
        &pi
    );

    if (!created) {
        result.errorMessage = L"CreateProcess failed: " + GetLastErrorString();
        return result;
    }

    result.processId = pi.dwProcessId;

    // Create shared memory for proxy config
    HANDLE hMapFile = NULL;
    if (!CreateSharedMemory(pi.dwProcessId, config, hMapFile)) {
        result.errorMessage = L"Failed to create shared memory for config";
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return result;
    }

    // Inject DLL
    std::wstring injectError;
    if (!InjectDll(pi.hProcess, dllPath, injectError)) {
        result.errorMessage = L"DLL injection failed: " + injectError;
        CloseHandle(hMapFile);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return result;
    }

    // Resume the main thread
    ResumeThread(pi.hThread);

    // Cleanup handles (shared memory stays open until launcher closes)
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    result.success = true;
    return result;
}

bool Injector::InjectDll(HANDLE hProcess, const std::wstring& dllPath, std::wstring& errorOut)
{
    // Calculate size needed for DLL path (in bytes, including null terminator)
    SIZE_T pathSize = (dllPath.length() + 1) * sizeof(wchar_t);

    // Allocate memory in target process
    LPVOID remoteMem = VirtualAllocEx(
        hProcess,
        NULL,
        pathSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (!remoteMem) {
        errorOut = L"VirtualAllocEx failed: " + GetLastErrorString();
        return false;
    }

    // Write DLL path to target process memory
    SIZE_T bytesWritten;
    BOOL written = WriteProcessMemory(
        hProcess,
        remoteMem,
        dllPath.c_str(),
        pathSize,
        &bytesWritten
    );

    if (!written || bytesWritten != pathSize) {
        errorOut = L"WriteProcessMemory failed: " + GetLastErrorString();
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        return false;
    }

    // Get LoadLibraryW address (same in all processes on same system)
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    if (!hKernel32) {
        errorOut = L"GetModuleHandleW(kernel32) failed";
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        return false;
    }

    LPTHREAD_START_ROUTINE loadLibraryAddr =
        reinterpret_cast<LPTHREAD_START_ROUTINE>(
            GetProcAddress(hKernel32, "LoadLibraryW"));

    if (!loadLibraryAddr) {
        errorOut = L"GetProcAddress(LoadLibraryW) failed";
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        return false;
    }

    // Create remote thread to call LoadLibraryW
    HANDLE hRemoteThread = CreateRemoteThread(
        hProcess,
        NULL,
        0,
        loadLibraryAddr,
        remoteMem,
        0,
        NULL
    );

    if (!hRemoteThread) {
        errorOut = L"CreateRemoteThread failed: " + GetLastErrorString();
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        return false;
    }

    // Wait for LoadLibraryW to complete
    DWORD waitResult = WaitForSingleObject(hRemoteThread, 10000);
    if (waitResult == WAIT_TIMEOUT) {
        errorOut = L"LoadLibraryW timed out";
        CloseHandle(hRemoteThread);
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        return false;
    }

    // Check if LoadLibraryW succeeded
    DWORD exitCode = 0;
    GetExitCodeThread(hRemoteThread, &exitCode);

    CloseHandle(hRemoteThread);
    VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);

    // exitCode is the return value of LoadLibraryW (HMODULE or NULL)
    if (exitCode == 0) {
        errorOut = L"LoadLibraryW returned NULL - DLL failed to load. Check DLL path: " + dllPath;
        return false;
    }

    return true;
}

bool Injector::CreateSharedMemory(DWORD processId, const ProxyConfig& config, HANDLE& hMapFile)
{
    // Format shared memory name
    wchar_t sharedMemName[256];
    swprintf_s(sharedMemName, SHARED_MEM_NAME_FORMAT, processId);

    // Create file mapping
    hMapFile = CreateFileMappingW(
        INVALID_HANDLE_VALUE,
        NULL,
        PAGE_READWRITE,
        0,
        static_cast<DWORD>(SHARED_MEM_SIZE),
        sharedMemName
    );

    if (!hMapFile) {
        return false;
    }

    // Map view and write config
    LPVOID pBuf = MapViewOfFile(
        hMapFile,
        FILE_MAP_ALL_ACCESS,
        0,
        0,
        SHARED_MEM_SIZE
    );

    if (!pBuf) {
        CloseHandle(hMapFile);
        hMapFile = NULL;
        return false;
    }

    memcpy(pBuf, &config, sizeof(ProxyConfig));
    UnmapViewOfFile(pBuf);

    return true;
}

bool Injector::IsProcess64Bit(HANDLE hProcess)
{
    BOOL isWow64 = FALSE;
    if (IsWow64Process(hProcess, &isWow64)) {
        SYSTEM_INFO si;
        GetNativeSystemInfo(&si);
        if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) {
            // On 64-bit Windows:
            // isWow64 == TRUE means 32-bit process
            // isWow64 == FALSE means 64-bit process
            return !isWow64;
        }
    }
    return false;  // 32-bit Windows, all processes are 32-bit
}

std::wstring Injector::GetLastErrorString()
{
    DWORD error = GetLastError();
    if (error == 0) {
        return L"No error";
    }

    LPWSTR buffer = nullptr;
    size_t size = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        error,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        reinterpret_cast<LPWSTR>(&buffer),
        0,
        NULL
    );

    std::wstring message(buffer, size);
    LocalFree(buffer);

    // Remove trailing newlines
    while (!message.empty() && (message.back() == L'\n' || message.back() == L'\r')) {
        message.pop_back();
    }

    return message + L" (Error " + std::to_wstring(error) + L")";
}

