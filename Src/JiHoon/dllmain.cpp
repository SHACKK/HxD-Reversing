#include "pch.h"

BYTE g_pOrgBytes[5] = { 0, };

BOOL InjectDll(HANDLE hProcess, LPCTSTR szDllName)
{
	HANDLE hThread;
	LPVOID pRemoteBuf;
	DWORD dwBufSize = (DWORD)(_tcslen(szDllName) + 1) * sizeof(TCHAR);
	FARPROC pThreadProc;

	pRemoteBuf = VirtualAllocEx(hProcess, NULL, dwBufSize, MEM_COMMIT, PAGE_READWRITE);
	if (pRemoteBuf == NULL)
		return FALSE;

	WriteProcessMemory(hProcess, pRemoteBuf, (LPVOID)szDllName, dwBufSize, NULL);

	pThreadProc = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryW");
	hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pThreadProc, pRemoteBuf, 0, NULL);
	WaitForSingleObject(hThread, INFINITE);

	VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);

	CloseHandle(hThread);

	return TRUE;
}

BOOL hook_by_code(LPCSTR szDllName, LPCSTR szFuncName, PROC pfnNew, PBYTE pOrgBytes)
{
	FARPROC pfnOrg;
	DWORD dwOldProtect, dwAddress;
	BYTE pBuf[5] = { 0xE9, 0, };
	PBYTE pByte;

	// 후킹 대상 API 주소를 구한다
	pfnOrg = (FARPROC)GetProcAddress(GetModuleHandleA(szDllName), szFuncName);
	pByte = (PBYTE)pfnOrg;

	// 만약 이미 후킹 되어 있다면 return FALSE
	if (pByte[0] == 0xE9)
		return FALSE;

	// 5 byte 패치를 위하여 메모리에 WRITE 속성 추가
	VirtualProtect((LPVOID)pfnOrg, 5, PAGE_EXECUTE_READWRITE, &dwOldProtect);

	// 기존 코드 (5 byte) 백업
	memcpy(pOrgBytes, pfnOrg, 5);

	// JMP 주소 계산 (E9 XXXX)
	// => XXXX = pfnNew - pfnOrg - 5
	dwAddress = (DWORD)pfnNew - (DWORD)pfnOrg - 5;
	memcpy(&pBuf[1], &dwAddress, 4);

	// Hook - 5 byte 패치 (JMP XXXX)
	memcpy(pfnOrg, pBuf, 5);

	// 메모리 속성 복원
	VirtualProtect((LPVOID)pfnOrg, 5, dwOldProtect, &dwOldProtect);

	return TRUE;
}


BOOL unhook_by_code(LPCSTR szDllName, LPCSTR szFuncName, PBYTE pOrgBytes)
{
	FARPROC pFunc;
	DWORD dwOldProtect;
	PBYTE pByte;

	// API 주소 구한다
	pFunc = GetProcAddress(GetModuleHandleA(szDllName), szFuncName);
	pByte = (PBYTE)pFunc;

	// 만약 이미 언후킹 되어 있다면 return FALSE
	if (pByte[0] != 0xE9)
		return FALSE;

	// 원래 코드(5 byte)를 덮어쓰기 위해 메모리에 WRITE 속성 추가
	VirtualProtect((LPVOID)pFunc, 5, PAGE_EXECUTE_READWRITE, &dwOldProtect);

	// Unhook
	memcpy(pFunc, pOrgBytes, 5);

	// 메모리 속성 복원
	VirtualProtect((LPVOID)pFunc, 5, dwOldProtect, &dwOldProtect);

	return TRUE;
}

bool IsSameArray(BYTE btFileSignature[], BYTE btFormat[], size_t tSize)
{
	for (int i = 0; i < (int)tSize; i++)
	{
		if (btFileSignature[i] != btFormat[i])
			return false;
	}
	return true;
}

std::wstring getExt(std::wstring strFilePath)
{
	return strFilePath.substr(strFilePath.find_last_of(L".") + 1);
}

std::wstring ParseExt(BYTE btFileSignature[4])
{
	BYTE btSignature_EXE[2] = { 0x4d, 0x5a };
	BYTE btSignature_JPG_1[4] = { 0xFF, 0xD8, 0xFF, 0xE0 };
	BYTE btSignature_JPG_2[4] = { 0xFF, 0xD8, 0xFF, 0xE8 };
	BYTE btSignature_PNG[4] = { 0x89, 0x50, 0x4E, 0x47 };
	BYTE btSignature_ZIP[4] = { 0x50, 0x4B, 0x03, 0x04 };

	if (IsSameArray(btFileSignature, btSignature_EXE, 2))
		return L"EXE File Detected!!";
	if (IsSameArray(btFileSignature, btSignature_JPG_1, 4) ||
		IsSameArray(btFileSignature, btSignature_JPG_2, 4))
		return L"JPG File Detected!!";
	if (IsSameArray(btFileSignature, btSignature_PNG, 4))
		return L"PNG File Detected!!";
	if (IsSameArray(btFileSignature, btSignature_ZIP, 4))
		return L"ZIP File Detected!!";
}

HANDLE WINAPI NewFindFirstFileW(
	LPCWSTR               lpFileName,
	DWORD                 dwDesiredAccess,
	DWORD                 dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD                 dwCreationDisposition,
	DWORD                 dwFlagsAndAttributes,
	HANDLE                hTemplateFile
)
{
	FILE* fUploadedFile = NULL;
	_wfopen_s(&fUploadedFile, lpFileName, L"rb");

	BYTE btFileSignature[4];
	size_t tReadSize = ::fread(&btFileSignature[0], sizeof(BYTE), 4, fUploadedFile);

	std::wstring strMessage = ParseExt(btFileSignature);
	MessageBox(NULL, strMessage.c_str(), L"Result", MB_OK);

	//unHook
	unhook_by_code("KernelBase.dll", "FindFirstFileW", g_pOrgBytes);

	//Original Function Call
	HANDLE nRet = CreateFileW(
		lpFileName,
		dwDesiredAccess,
		dwShareMode,
		lpSecurityAttributes,
		dwCreationDisposition,
		dwFlagsAndAttributes,
		hTemplateFile);

	//Hook
	hook_by_code("KernelBase.dll", "FindFirstFileW", (PROC)NewFindFirstFileW, g_pOrgBytes);

	return nRet;
}

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		hook_by_code("KernelBase.dll", "FindFirstFileW", (PROC)NewFindFirstFileW, g_pOrgBytes);
		break;
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}