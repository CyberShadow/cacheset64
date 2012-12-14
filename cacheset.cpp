#include <windows.h>
#include <stdio.h>

#pragma comment(lib, "advapi32")

BOOL GetPrivilege(HANDLE TokenHandle, LPCSTR lpName, int flags)
{
	BOOL bResult;
	DWORD dwBufferLength;
	LUID luid;
	TOKEN_PRIVILEGES tpPreviousState;
	TOKEN_PRIVILEGES tpNewState;

	dwBufferLength = 16;
	bResult = LookupPrivilegeValueA(0, lpName, &luid);
	if (bResult)
	{
		tpNewState.PrivilegeCount = 1;
		tpNewState.Privileges[0].Luid = luid;
		tpNewState.Privileges[0].Attributes = 0;
		bResult = AdjustTokenPrivileges(TokenHandle, 0, &tpNewState, (LPBYTE)&(tpNewState.Privileges[1]) - (LPBYTE)&tpNewState, &tpPreviousState, &dwBufferLength);
		if (bResult)
		{
			tpPreviousState.PrivilegeCount = 1;
			tpPreviousState.Privileges[0].Luid = luid;
			tpPreviousState.Privileges[0].Attributes = flags != 0 ? 2 : 0;
			bResult = AdjustTokenPrivileges(TokenHandle, 0, &tpPreviousState, dwBufferLength, 0, 0);
		}
	}
	return bResult;
}

// From http://www2.alter.org.ua/soft/win/cacheset/
#define SYSTEMCACHEINFORMATION 0x15
struct SYSTEM_CACHE_INFORMATION
{
	ULONG_PTR	CurrentSize;
	ULONG_PTR	PeakSize;
	ULONG_PTR	PageFaultCount;
	ULONG_PTR	MinimumWorkingSet;
	ULONG_PTR	MaximumWorkingSet;
	ULONG_PTR	TransitionSharedPages;
	ULONG_PTR	PeakTransitionSharedPages;
	DWORD       Unused[2];
};

int main()
{
	HANDLE hProcess = GetCurrentProcess();
	HANDLE hToken;
	if (!OpenProcessToken(hProcess, TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken))
	{
		fprintf(stderr, "Can't open current process token\n");
		return 1;
	}

	if (!GetPrivilege(hToken, "SeIncreaseQuotaPrivilege", 1))
	{
		fprintf(stderr, "Can't get SeIncreaseQuotaPrivilege\n");
		return 1;
	}

	CloseHandle(hToken);

	HMODULE ntdll = LoadLibrary("ntdll.dll");
	if (!ntdll)
	{
		fprintf(stderr, "Can't load ntdll.dll, wrong Windows version?\n");
		return 1;
	}

	typedef DWORD NTSTATUS; // ?
	NTSTATUS (WINAPI *NtSetSystemInformation)(INT, PVOID, ULONG) = (NTSTATUS (WINAPI *)(INT, PVOID, ULONG))GetProcAddress(ntdll, "NtSetSystemInformation");
	NTSTATUS (WINAPI *NtQuerySystemInformation)(INT, PVOID, ULONG, PULONG) = (NTSTATUS (WINAPI *)(INT, PVOID, ULONG, PULONG))GetProcAddress(ntdll, "NtQuerySystemInformation");
	if (!NtSetSystemInformation || !NtQuerySystemInformation)
	{
		fprintf(stderr, "Can't get function addresses, wrong Windows version?\n");
		return 1;
	}

	SYSTEM_CACHE_INFORMATION sci = {0};

	// printf("Struct size = 0x%X\n", sizeof(sci));

	ULONG dwRead = 0;
	NTSTATUS dwStatus = NtQuerySystemInformation(SYSTEMCACHEINFORMATION, &sci, sizeof(sci), &dwRead);
	if (dwStatus != 0)
	{
		fprintf(stderr, "NtQuerySystemInformation error %08X\n", dwStatus);
		return 1;
	}

	sci.MinimumWorkingSet *= 4096;
	sci.MaximumWorkingSet *= 4096;

	printf("Current minimum working set size: %Id\n", sci.MinimumWorkingSet);
	printf("Current maximum working set size: %Id\n", sci.MaximumWorkingSet);

	printf("New minimum working set size: "); scanf("%Id", &sci.MinimumWorkingSet);
	printf("New maximum working set size: "); scanf("%Id", &sci.MaximumWorkingSet);

//	sci.MinimumWorkingSet = 0x100000000LU;
//	sci.MaximumWorkingSet = 0x400000000LU;

	dwStatus = NtSetSystemInformation(SYSTEMCACHEINFORMATION, &sci, dwRead);
	if (dwStatus != 0)
	{
		fprintf(stderr, "NtSetSystemInformation error %08X\n", dwStatus);
		return 1;
	}

	return 0;
}
