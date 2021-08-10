#include"../driver-lib/export.h"
#include"../driver-lib/NtStruct.h"
#include"../driver-lib/hook.h"
#include"../driver-lib/templateExportFunc.h"
#include"../driver-lib/exclusivity.h"
#include<intrin.h>


#define dc(a) decltype(a)
#define int3 __debugbreak()

void myKeBugCheckEx(
	ULONG     BugCheckCode,
	ULONG_PTR BugCheckParameter1,
	ULONG_PTR BugCheckParameter2,
	ULONG_PTR BugCheckParameter3,
	ULONG_PTR BugCheckParameter4
);

typedef struct _SYSTEM_BIGPOOL_ENTRY
{
	union {
		PVOID VirtualAddress;
		ULONG_PTR NonPaged : 1;
	};
	ULONG_PTR SizeInBytes;
	union {
		UCHAR Tag[4];
		ULONG TagUlong;
	};
} SYSTEM_BIGPOOL_ENTRY, * PSYSTEM_BIGPOOL_ENTRY;
typedef struct _SYSTEM_BIGPOOL_INFORMATION
{
	ULONG Count;
	SYSTEM_BIGPOOL_ENTRY AllocatedInfo[1];
} SYSTEM_BIGPOOL_INFORMATION, * PSYSTEM_BIGPOOL_INFORMATION;


typedef struct _MMPTE_HARDWARE            // 18 elements, 0x8 bytes (sizeof)
{
	/*0x000*/     UINT64       Valid : 1;               // 0 BitPosition
	/*0x000*/     UINT64       Dirty1 : 1;              // 1 BitPosition
	/*0x000*/     UINT64       Owner : 1;               // 2 BitPosition
	/*0x000*/     UINT64       WriteThrough : 1;        // 3 BitPosition
	/*0x000*/     UINT64       CacheDisable : 1;        // 4 BitPosition
	/*0x000*/     UINT64       Accessed : 1;            // 5 BitPosition
	/*0x000*/     UINT64       Dirty : 1;               // 6 BitPosition
	/*0x000*/     UINT64       LargePage : 1;           // 7 BitPosition
	/*0x000*/     UINT64       Global : 1;              // 8 BitPosition
	/*0x000*/     UINT64       CopyOnWrite : 1;         // 9 BitPosition
	/*0x000*/     UINT64       Unused : 1;              // 10 BitPosition
	/*0x000*/     UINT64       Write : 1;               // 11 BitPosition
	/*0x000*/     UINT64       PageFrameNumber : 36;    // 12 BitPosition
	/*0x000*/     UINT64       ReservedForHardware : 4; // 48 BitPosition
	/*0x000*/     UINT64       ReservedForSoftware : 4; // 52 BitPosition
	/*0x000*/     UINT64       WsleAge : 4;             // 56 BitPosition
	/*0x000*/     UINT64       WsleProtection : 3;      // 60 BitPosition
	/*0x000*/     UINT64       NoExecute : 1;           // 63 BitPosition
}MMPTE_HARDWARE, * PMMPTE_HARDWARE;

#define MM_PTE_VALID_MASK         0x1
#if defined(NT_UP)
#define MM_PTE_WRITE_MASK         0x2
#else
#define MM_PTE_WRITE_MASK         0x800
#endif
#define MM_PTE_OWNER_MASK         0x4
#define MM_PTE_WRITE_THROUGH_MASK 0x8
#define MM_PTE_CACHE_DISABLE_MASK 0x10
#define MM_PTE_ACCESS_MASK        0x20
#if defined(NT_UP)
#define MM_PTE_DIRTY_MASK         0x40
#else
#define MM_PTE_DIRTY_MASK         0x42
#endif
#define MM_PTE_LARGE_PAGE_MASK    0x80
#define MM_PTE_GLOBAL_MASK        0x100
#define MM_PTE_COPY_ON_WRITE_MASK 0x200
#define MM_PTE_PROTOTYPE_MASK     0x400
#define MM_PTE_TRANSITION_MASK    0x800

typedef struct _MMPTE         // 1 elements, 0x8 bytes (sizeof)
{
	/*0x000*/     union {
		MMPTE_HARDWARE  Hard;
		ULONG64         Long;
	} u; // 9 elements, 0x8 bytes (sizeof)
}MMPTE, * PMMPTE;

ULONG64 g_PTE_BASE = 0xFFFFF68000000000;
ULONG64 g_PDE_BASE = 0xFFFFF6FB40000000;
ULONG64 g_PPE_BASE = 0xFFFFF6FB7DA00000;
ULONG64 g_PXE_BASE = 0xFFFFF6FB7DBED000;

typedef struct _HOOK_CTX
{
	ULONG64 rax;
	ULONG64 rcx;
	ULONG64 rdx;
	ULONG64 rbx;
	ULONG64 rbp;
	ULONG64 rsi;
	ULONG64 rdi;
	ULONG64 r8;
	ULONG64 r9;
	ULONG64 r10;
	ULONG64 r11;
	ULONG64 r12;
	ULONG64 r13;
	ULONG64 r14;
	ULONG64 r15;
	ULONG64 Rflags;
	ULONG64 rsp;
}HOOK_CTX, * PHOOK_CTX;

VOID KiRetireDpcList(
	PKPRCB7 Prcb
);

using pfnCapture = void(*)(CONTEXT* ctx);
int count = 0;
ULONGLONG nt_DbgPrint;
RTL_OSVERSIONINFOW version;
extern "C" {
	void PrintfInterpretCount();
	void PrintfRecoverCount(ULONG64 addr);
	extern VOID AdjustStackCallPointer(
		IN ULONG_PTR NewStackPointer,
		IN PVOID StartAddress,
		IN PVOID Argument);
	extern VOID HookRtlCaptureContext();
	extern ULONGLONG GetRsp();
	CONTEXT hookCtx;
	CONTEXT* phookCtx = &hookCtx;
	pfnCapture oriRtlCaptureContext;
	void MyRtlCaptureContext(CONTEXT* ctx);
	ULONGLONG callFromRip;
	ULONGLONG errorCode;
	ULONGLONG tRegister;
	char GetCpuIndex();
	extern void EnableInterrupts();
	ULONG_PTR g_KiRetireDpcList;
	ULONG_PTR pKiRetireDpcList;
	ULONG g_MaxCpu;
	ULONG64 g_CpuContextAddress = 0;
	KDPC  g_TempDpc[10];
	extern VOID BackTo1942();
	extern VOID editRip();
	extern VOID HookKiRetireDpcList();
	bool ifFindErrorCode;
	ULONG64 switchRsp;
	ULONG64 addrKiScanReadyQueues;
	ULONG64 probablyContextPoll[100];
	ULONG64 KiProcessBlock;
	extern void DPC_FIX();
	ULONG64 nextintruc;
	NTSYSCALLAPI NTSTATUS NtOpenProcess(
		PHANDLE            ProcessHandle,
		ACCESS_MASK        DesiredAccess,
		POBJECT_ATTRIBUTES ObjectAttributes,
		PCLIENT_ID         ClientId
	);
	NTSYSCALLAPI NTSTATUS ObRegisterCallbacks(
		POB_CALLBACK_REGISTRATION CallbackRegistration,
		PVOID* RegistrationHandle
	);
	void VistaAll_DpcInterceptor(
		PKDPC InDpc,
		PVOID InDeferredContext,
		PVOID InSystemArgument1,
		PVOID InSystemArgument2);
	ULONG64 KiWaitNever;
	ULONG64 KiWaitAlways;
	PULONG64    pKiWaitNever = &KiWaitNever;
	PULONG64    pKiWaitAlways = &KiWaitAlways;
	ULONG64 addrKiPageFault;
	extern void
		hookKiPageFault(); PMMPTE GetPxeAddress(PVOID addr)
	{
		return (PMMPTE)(((((ULONG64)addr & 0xffffffffffff) >> 39) << 3) + g_PXE_BASE);
	}
	PMMPTE GetPpeAddress(PVOID addr)
	{
		return (PMMPTE)(((((ULONG64)addr & 0xffffffffffff) >> 30) << 3) + g_PPE_BASE);
	}
	PMMPTE GetPdeAddress(PVOID addr)
	{
		return (PMMPTE)(((((ULONG64)addr & 0xffffffffffff) >> 21) << 3) + g_PDE_BASE);
	}
	PMMPTE GetPteAddress(PVOID addr)
	{
		return (PMMPTE)(((((ULONG64)addr & 0xffffffffffff) >> 12) << 3) + g_PTE_BASE);
	}
}
using orf3 = NTSTATUS(*)();
orf3 oriKipagefault;
using orf4 = NTSTATUS(*)(PRTL_OSVERSIONINFOW lpVersionInformation);
orf4 oriRtlGetversion;
NTSTATUS myRtlGetVersion(
	PRTL_OSVERSIONINFOW lpVersionInformation
);
PVOID GetVirtualAddressMappedByPte(PMMPTE pte)
{
	return (PVOID)(((((ULONG64)pte - g_PTE_BASE) >> 3) << 12) | 0xffff000000000000);
}
PVOID GetVirtualAddressMappedByPde(PMMPTE pde)
{
	return (PVOID)(((((ULONG64)pde - g_PDE_BASE) >> 3) << 21) | 0xffff000000000000);
}
PVOID GetVirtualAddressMappedByPpe(PMMPTE ppe)
{
	return (PVOID)(((((ULONG64)ppe - g_PPE_BASE) >> 3) << 30) | 0xffff000000000000);
}
PVOID GetVirtualAddressMappedByPxe(PMMPTE pxe)
{
	return (PVOID)(((((ULONG64)pxe - g_PXE_BASE) >> 3) << 39) | 0xffff000000000000);
}
//PMMPTE GetPxeAddress(PVOID addr)
//{
//	return (PMMPTE)(((((ULONG64)addr & 0xffffffffffff) >> 39) << 3) + g_PXE_BASE);
//}
//PMMPTE GetPpeAddress(PVOID addr)
//{
//	return (PMMPTE)(((((ULONG64)addr & 0xffffffffffff) >> 30) << 3) + g_PPE_BASE);
//}
//PMMPTE GetPdeAddress(PVOID addr)
//{
//	return (PMMPTE)(((((ULONG64)addr & 0xffffffffffff) >> 21) << 3) + g_PDE_BASE);
//}
//PMMPTE GetPteAddress(PVOID addr)
//{
//	return (PMMPTE)(((((ULONG64)addr & 0xffffffffffff) >> 12) << 3) + g_PTE_BASE);
//}
BOOLEAN CheckSubValue(ULONGLONG InValue)
{
	ULONG            i;
	ULONG            Result;
	UCHAR* Chars = (UCHAR*)&InValue;

	// random values will have a result around 120...
	Result = 0;

	for (i = 0; i < 8; i++)
	{

		Result += ((Chars[i] & 0xF0) >> 4) + (Chars[i] & 0x0F);
	}

	// the maximum value is 240, so this should be safe...
	if (Result < 70)
		return TRUE;

	return FALSE;
}

BOOLEAN PgIsPatchGuardContext(void* Ptr)
{
	ULONGLONG        Value = (ULONGLONG)Ptr;
	UCHAR* Chars = (UCHAR*)&Value;
	LONG            i;

	// those are sufficient proves for canonical pointers...
	if ((Value & 0xFFFF000000000000) == 0xFFFF000000000000)
		return FALSE;

	if ((Value & 0xFFFF000000000000) == 0)
		return FALSE;


	// sieve out other common values...
	if (CheckSubValue(Value) || CheckSubValue(~Value))
		return FALSE;

	if (Ptr == NULL)
		return FALSE;

	//This must be the last check and filters latin-char UTF16 strings...
	for (i = 7; i >= 0; i -= 2)
	{
		if (Chars[i] != 0)
			return TRUE;
	}

	// this should only return true if the pointer is a unicode string!!!
	return FALSE;
}
void VistaAll_DpcInterceptor(
	PKDPC InDpc,
	PVOID InDeferredContext,
	PVOID InSystemArgument1,
	PVOID InSystemArgument2)
{
	ULONGLONG        Routine = (ULONGLONG)InDpc->DeferredRoutine;

	__try
	{
		if ((Routine >= 0xFFFFFA8000000000) &&
			(Routine <= 0xFFFFFAA000000000))
		{
		}
		
			if (!PgIsPatchGuardContext(InDeferredContext))
				InDpc->DeferredRoutine(
					InDpc,
					InDeferredContext,
					InSystemArgument1,
					InSystemArgument2);
		
		else
			InDpc->DeferredRoutine(
				InDpc,
				InDeferredContext,
				InSystemArgument1,
				InSystemArgument2);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		DbgPrint("exception from PatchGuard Dpc!\n");
	}
	//int3;
}
NTSTATUS ScanBigPool()
{
	PSYSTEM_BIGPOOL_INFORMATION pBigPoolInfo;
	ULONG64 ReturnLength = 0;
	NTSTATUS status;
	ULONG i = 0;
	int num = 0;


	pBigPoolInfo = (PSYSTEM_BIGPOOL_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, sizeof(SYSTEM_BIGPOOL_INFORMATION), 'ttt');
	status = ZwQuerySystemInformation(0x42/*SystemBigPoolInformation*/, pBigPoolInfo, sizeof(SYSTEM_BIGPOOL_INFORMATION), (ULONG*)&ReturnLength);
	DbgPrint("pBigPoolInfo->Count - %d \n", pBigPoolInfo->Count);
	DbgPrint("ReturnLength - %p \n", ReturnLength);
	ExFreePool(pBigPoolInfo);
	pBigPoolInfo = (PSYSTEM_BIGPOOL_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, ReturnLength + 0x1000, 'ttt');
	if (!pBigPoolInfo)
		return STATUS_UNSUCCESSFUL;
	status = ZwQuerySystemInformation(0x42, pBigPoolInfo, ReturnLength + 0x1000, (ULONG*)&ReturnLength);
	if (status != STATUS_SUCCESS)
	{
		DbgPrint("query BigPoolInfo failed: %p\n", status);
		return status;
	}
	DbgPrint("pBigPoolInfo: %p\n", pBigPoolInfo);

	//处理多核问题
	auto pool = ExclGainExclusivity();
	for (i = 0; i < pBigPoolInfo->Count; i++)
	{
		PVOID addr = pBigPoolInfo->AllocatedInfo[i].VirtualAddress;
		ULONG64 size = (ULONG64)pBigPoolInfo->AllocatedInfo[i].SizeInBytes;
		PULONG64 ppte = (PULONG64)GetPteAddress(addr);
		ULONG64 pte = *ppte;
		PULONG64 ppde = (PULONG64)GetPdeAddress(addr);
		ULONG64 pde = *ppde;

		

		/*
		@需要进一步判断size
		*/
		if (size > 0x4000)
		{

	/*
	@ULONG64 pgContextAddr = bugCheckParameter[0] - 0xA3A03F5891C8B4E8
	@ reasonInfoAddr = bugCheckParameter[1] - 0xB3B74BDEE4453415;
	*/
			
			/*
			@不能直接设置不可执行，应该再次判断一下这个pool到底是不是PatchGuard的
			*/
			if (pde & 0x80 && (pde & 1)) {//big page 2M一页
				//DbgPrint("big page find ! \n");
				pde |= 0x8000000000000000;
				*ppde = pde;
				//DbgPrint("big page addr: %p, size: %p, pde: %p, nom\n", addr, size, pde);
				num++;
			}
			else {

				if ((pte & 0x8000000000000000) == 0 && (pte & 1)) {
					//页面设置不可执行
					pte |= 0x8000000000000000;
					*ppte = pte;
					//DbgPrint("addr: %p, size: %p, pte: %p, nom\n", addr, size, pte);
					num += 1;
				}
			}
		}
	}
	ExclReleaseExclusivity(pool);
	DbgPrint("num: %d\n", num);
	ExFreePool(pBigPoolInfo);
	return status;
}
bool GetDpcPassword()
{
	ULONG64 KeSetTimer = 0;
	PUCHAR StartSearchAddress = 0;
	PUCHAR EndSearchAddress = 0;

	INT64   iOffset = 0;

	PUCHAR i = NULL;

	KeSetTimer = (ULONG64)GetProcAddress(L"KeSetTimerEx");
	auto offset = *(ULONG*)(KeSetTimer + 13);
	auto rip = KeSetTimer + 0xC;
	ULONG64 KiSetTimerEx = rip + (LONG)offset+5;

	//int3;
	StartSearchAddress = (PUCHAR)KiSetTimerEx;
	EndSearchAddress = StartSearchAddress + 500;


	for (i = StartSearchAddress; i < EndSearchAddress; i++)
	{
		if (*i == 0x48 && *(i + 1) == 0x8B && *(i + 2) == 0x05)
		{
			memcpy(&iOffset, i + 3, 4);
			//兩個密碼的值
			*pKiWaitNever = *(PULONG64)(iOffset + (ULONG64)i + 7);
			DbgPrint("KiWaitNever = %llx\n", pKiWaitNever);
			i = i + 7;
			memcpy(&iOffset, i + 3, 4);
			*pKiWaitAlways = *(PULONG64)(iOffset + (ULONG64)i + 7);
			DbgPrint("KiWaitAlways = %llx\n", pKiWaitAlways);
			return TRUE;
		}
	}
	return false;
}
KDPC* TransTimerDPCEx(PKTIMER Timer, ULONG64 KiWaitNever, ULONG64 KiWaitAlways)
{
	ULONG64 DPC = (ULONG64)Timer->Dpc;     //Time 
	DPC ^= KiWaitNever;
	DPC = _rotl64(DPC, (UCHAR)(KiWaitNever & 0xFF));
	DPC ^= (ULONG64)Timer;
	DPC = _byteswap_uint64(DPC);
	DPC ^= KiWaitAlways;
	return (KDPC*)DPC;
}
NTSTATUS myObRegisterCallbacks(
	POB_CALLBACK_REGISTRATION CallbackRegistration,
	PVOID* RegistrationHandle
);
using orf = NTSTATUS(*)(POB_CALLBACK_REGISTRATION, PVOID* );
orf oriOb;
using orf2 = void(*)(
	ULONG     BugCheckCode,
	ULONG_PTR BugCheckParameter1,
	ULONG_PTR BugCheckParameter2,
	ULONG_PTR BugCheckParameter3,
	ULONG_PTR BugCheckParameter4
	);
orf2 oriKebugcheck;

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT pDrvObject, PUNICODE_STRING pRegPath)
{
	/*
	@判断是否开了kpti，会影响很多代码的运行
	*/
	/*auto msr_syscall  = __readmsr(0xC0000082);
	DbgPrint("msr[0xC0000082 = %p\n", msr_syscall);
	MySleep(10000);
	KeBugCheck(0xffffffff);*/


	version.dwOSVersionInfoSize = sizeof(version);
	RtlGetVersion(&version);
	DbgPrint("os version: \n  \
		MajorVersion = %d \n \
		MinorVersion = %d \n \
		BuildNumber = %d \n \
		CSDVersion = %s \n", version.dwMajorVersion, version.dwMinorVersion, version.dwBuildNumber, version.szCSDVersion);

	if (!(PVOID)KeBugCheckEx)
		return STATUS_UNSUCCESSFUL;



	PVOID orifunc;
	ULONG patchsize;
	HOOK::Hook_Init();
	ulong patchSize;

	auto addrKiRetireDpcList = FindPattern<sizeof("\xbd\x01\x00\x00\x00\x48\x8b\xd9\x48\x89\xb4\x24\xb8\x00\x00\x00")>(KeSetEvent, "\xbd\x01\x00\x00\x00\x48\x8b\xd9\x48\x89\xb4\x24\xb8\x00\x00\x00", 0x100000);
	addrKiScanReadyQueues = FindPattern<sizeof("\x49\x8b\xc1\x48\xc1\xe8\x08\x48\x89\x41\x20")>(KeSetEvent, "\x49\x8b\xc1\x48\xc1\xe8\x08\x48\x89\x41\x20", 0x100000);

	pKiRetireDpcList = addrKiRetireDpcList - 0x15;
	addrKiScanReadyQueues = addrKiScanReadyQueues - 0x29;
	DbgPrint("pfnKiRetireDpcList = %p\n", pKiRetireDpcList);
	DbgPrint("addrKiScanReadyQueues = %p\n", addrKiScanReadyQueues);
	//HOOK::HookKernelApi(RtlCaptureContext, MyRtlCaptureContext, (PVOID*)&oriRtlCaptureContext, &patchSize);
	/*HOOK::HookKernelApi((PVOID)pKiRetireDpcList, (PVOID)HookKiRetireDpcList, (PVOID*)&g_KiRetireDpcList, &patchSize);*/
	ULONG patch;
	//HOOK::HookKernelApi(KeBugCheckEx, myKeBugCheckEx, (PVOID*)&oriKebugcheck, &patch);
	
	/*
	@hook KiPageFault
	*/
	auto hookstart = FindPattern<sizeof"\xB9\x02\x01\x00\xC0\xf\x32\x89\x45\xE8">(GetProcAddress(L"ZwSetTimerEx"), "\xB9\x02\x01\x00\xC0\xf\x32\x89\x45\xE8",0x10000);
	//int3;
	if (hookstart) {

		hookstart = hookstart - 0x22e;
		addrKiPageFault = hookstart + 0x10;
		DbgPrint("KiPageFault = %p", hookstart);
		HOOK::HookKernelApi((PVOID)hookstart, hookKiPageFault, (PVOID*)&oriKipagefault, &patch);
	}
	else
		DbgPrint("KiPageFault find failed!");


	nt_DbgPrint = (ULONGLONG)GetProcAddress(L"DbgPrint");
	
	g_CpuContextAddress = (ULONG64)ExAllocatePool(NonPagedPool, 0x200 * g_MaxCpu + 0x1000);
	RtlZeroMemory((PVOID)g_CpuContextAddress, 0x200 * g_MaxCpu);
	RtlZeroMemory(g_TempDpc, sizeof(KDPC) * 10);

	g_MaxCpu = KeNumberProcessors;

	/*auto hookStart = FindPattern<sizeof("\xFF\x94\x24\xC8\x00\x00\x00")>((PVOID)pKiRetireDpcList, "\xFF\x94\x24\xC8\x00\x00\x00", 0x1000);
	if (hookStart) {
		nextintruc = hookStart + 0x7;
		hookStart -= 0xC;
		auto t = WPOFFx64();
		UCHAR jmp_code[] = "\x90\x90\x90\x90\x90\xFF\x25\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF";
		ULONG64 funcaddr = (ULONG64)DPC_FIX;
		memcpy(jmp_code + 11, &funcaddr, 8);
		memcpy((void*)hookStart, jmp_code, sizeof(jmp_code)-1);
		WPONx64(t);

	}*/






	//------------------------------------------------------------------------------------------------------








	auto p = GetProcAddress(L"KeSetTimeIncrement");
	auto poffset = *(ULONG32*)((ULONG64)p + 0x25);
	auto pnext = (ULONG64)p + 0x29;
	KiProcessBlock = pnext + poffset;

	DbgPrint("KiProcessBlock = %p \n", KiProcessBlock);

	if (!GetDpcPassword()) {
		DbgPrint("GetDpcPassword failed!\n");
		return STATUS_SUCCESS;
	}
	/*
	@把pg的dpc存放地点ban了
	*/
	//ULONG dpcNumber = 0;
	//for (int i = 0; i < KeNumberProcessors; i++)
	//{
	//	//int3;
	//	ULONG64* p = (ULONG64*)KiProcessBlock;
	//	ULONG64 pKprcb = p[i];
	//	DbgPrint("KiProcessBlock[%d] = %p\n",i ,p[i]);
	//	auto p2 = pKprcb + 0x648;
	//	auto p3 = pKprcb + 0x5f8;

	//	KIRQL t = WPOFFx64();

	//	memset((ULONG64*)p2, 0,8);

	//	for (int i = 0; i < 8; i++) {
	//		memset((ULONG64*)p3+i, 0, 8);
	//	}
	//	WPONx64(t);

	//	//遍历所有DPC
	//	using namespace win7;
	//	KTIMER_TABLE* pKtimeTable = (KTIMER_TABLE*)(pKprcb + 0x2200);
	//	KTIMER_TABLE_ENTRY* pKimeTableEntryStart = pKtimeTable->TimerEntries;

	//	LIST_ENTRY* listStart;
	//	LIST_ENTRY* listEnd;
	//	for (i = 0; i < 256; i++) {
	//		{
	//			listEnd = (dc(listEnd))&pKimeTableEntryStart->Entry;
	//			listStart = pKimeTableEntryStart->Entry.Flink;
	//			while (listStart != listEnd) {
	//				KTIMER* kTimer = CONTAINING_RECORD(listStart, KTIMER, TimerListEntry);
	//				if (MmIsAddressValid(kTimer)) {
	//					//DbgPrint("定时器对象地址%p \n", kTimer);
	//					//DbgPrint("触发周期 ms %d\n", kTimer->Period);
	//					auto dpc = TransTimerDPCEx(kTimer, (ULONG64)KiWaitNever, KiWaitAlways);
	//					if (MmIsAddressValid(dpc)) {
	//						dpcNumber++;
	//						/*
	//						@Dpc的DeferredRoutine
	//						*/
	//						//DbgPrint("DeferredRoutine %p\n", dpc->DeferredRoutine);

	//						/*if (PgIsPatchGuardContext(dpc->DeferredContext)) {
	//							DbgPrint("取消地址为 %p的定时器 \n", kTimer);
	//							KeCancelTimer(kTimer);
	//						}*/
	//					}
	//				}
	//				listStart = listStart->Flink;
	//			}
	//			pKimeTableEntryStart += 1;
	//		}

	//	}
	//}

	//DbgPrint("Timer-Dpc 个数为 %d\n", dpcNumber);

	ScanBigPool();







	/*ULONG patchsizea;
	HOOK::HookKernelApi(RtlGetVersion, myRtlGetVersion, (PVOID*)&oriRtlGetversion, &patchsizea);*/






	




































	pDrvObject->DriverUnload = DriverUnload;
	return STATUS_SUCCESS;
}
NTSTATUS myRtlGetVersion(
	PRTL_OSVERSIONINFOW lpVersionInformation
)
{
	lpVersionInformation->dwBuildNumber = 7603;
	lpVersionInformation->dwMajorVersion = 6;
	lpVersionInformation->dwMinorVersion = 2;
	lpVersionInformation->dwPlatformId = 10;
	return oriRtlGetversion(lpVersionInformation);
}

NTSTATUS myObRegisterCallbacks(
	POB_CALLBACK_REGISTRATION CallbackRegistration,
	PVOID* RegistrationHandle
)
{
	auto p = PsGetProcessImageFileName(IoGetCurrentProcess());
	DbgPrint("call ObRegisterCallbacks  is %s\n", p);
	return oriOb(CallbackRegistration, RegistrationHandle);
}
void myKeBugCheckEx(
	ULONG     BugCheckCode,
	ULONG_PTR BugCheckParameter1,
	ULONG_PTR BugCheckParameter2,
	ULONG_PTR BugCheckParameter3,
	ULONG_PTR BugCheckParameter4
)
{
	return oriKebugcheck(BugCheckCode, BugCheckParameter1, BugCheckParameter2, BugCheckParameter3, BugCheckParameter4);
}
VOID
PgTempDpc(
	IN struct _KDPC* Dpc,
	IN PVOID DeferredContext,
	IN PVOID SystemArgument1,
	IN PVOID SystemArgument2
)
{
	//dpcdata清空
	//int3;
	auto _cpu = KeGetCurrentProcessorNumber();
	DbgPrint("fake Dpc excute  on process %d\n", _cpu);
	auto prcb = *(ULONG64*)(KiProcessBlock+_cpu*8);
	win7::KDPC_DATA* dpcdata = (win7::KDPC_DATA*)(prcb + 0x2180);
	DbgPrint("DpcQueueDepth%d \n", dpcdata->DpcQueueDepth);
	
	dpcdata->DpcQueueDepth = 0;

	PLIST_ENTRY ListHead = &dpcdata->DpcListHead;
	ListHead = *((PLIST_ENTRY volatile*)&ListHead->Flink);

	//dpcdata->DpcListHead.Flink = &dpcdata->DpcListHead;

	return;
}
void MyRtlCaptureContext(CONTEXT* ctx)
{	
	/*
	@sub rsp,58h 
	*/
	ULONGLONG _rsp = (ULONGLONG)_AddressOfReturnAddress();
	callFromRip = (ULONGLONG)_ReturnAddress();
	errorCode = *(ULONG64*)(_rsp + 0x48);

	oriRtlCaptureContext(ctx);

	auto process = PsGetCurrentProcess();
	//DbgPrint("process in %s\n", (ULONG64)process + 0x2e0);

	//PCONTEXT pCtx = (PCONTEXT)(ctx->rcx);

	//callFromRip = *(ULONG64*)(ctx->Rsp);
	//errorCode = *(ULONG64*)(ctx->rsp+0x48);

	//oriRtlCaptureContext((PCONTEXT)(ctx->rcx));


	if (callFromRip >= (dc(callFromRip))KeBugCheckEx && callFromRip <= (dc(callFromRip))KeBugCheckEx + 0x100)
	{
		//因为不是汇编，手动控制不了开辟栈帧的大小,只能堆栈里回溯错误码


		//unhook DbgPrint
		if (nt_DbgPrint) {
			KIRQL t = WPOFFx64();
			_InterlockedExchange8((char*)nt_DbgPrint, 0x4c);

			//做一些其他的hook操作
			//_InterlockedExchange8((char*)addrKiScanReadyQueues, 0xc3);


			WPONx64(t);



		}

		


		if (errorCode == 0x109) {
			DbgPrint("bugcheck call from PatchGuard!\n");

			//判断IRQL
			KIRQL irql = KeGetCurrentIrql();
			if (irql == PASSIVE_LEVEL)
			{
				DbgPrint("PatchGuard is PASSIVE_LEVEL!\n");
				//PCHAR currentThread = (PCHAR)PsGetCurrentThread();
				////+0x388 StartAddress     : 0xfffff800`03e9e910 Void
				//PVOID startRoutine = *(PVOID**)(currentThread + 0x388);
				//PVOID stackPointer = IoGetInitialStack();
				//AdjustStackCallPointer(
				//	(ULONG_PTR)stackPointer - 0x8,
				//	startRoutine,
				//	NULL);

				/*
				@直接死循环
				*/
				FAST_MUTEX WaitAlways;

				/*ExInitializeFastMutex(&WaitAlways);
				ExAcquireFastMutex(&WaitAlways);
				ExAcquireFastMutex(&WaitAlways);*/

				
			}
			else if (irql == DISPATCH_LEVEL)
			{
				
				//走到这里来已经是109 bug check了
				//vmware的网络驱动会影响这里代码的运行

					//DbgPrint("PatchGuard is DISPATCH_LEVEL!\n");
					////int3;
					//PCHAR CurrentThread = (PCHAR)PsGetCurrentThread();
					//PVOID StartRoutine = *(PVOID**)(CurrentThread + 0x388);
					//PVOID StackPointer = IoGetInitialStack();//KeGetCurrentThread()->InitialStack;
					//auto p = KeGetCurrentThread();
					//ULONG64 StackLimit = *(ULONG64*)((ULONG64)p + 0x30);
					//ULONG64 StackBase = *(ULONG64*)((ULONG64)p + 0x278);
					//
					////int3;

					//CHAR  Cpu = GetCpuIndex();
					//KeInitializeDpc(&g_TempDpc[Cpu],
					//	PgTempDpc,
					//	NULL);
					//KeSetTargetProcessorDpc(&g_TempDpc[Cpu], (CCHAR)Cpu);
					//KeInsertQueueDpc(&g_TempDpc[Cpu], NULL, NULL);

					//BackTo1942();

				

			}
			

		}
	}
	else
	{
		//DbgPrint("call from %p\n", callFromRip);
	}


	return;
}

void PrintfInterpretCount()
{
	static ULONG count = 0;
	count++;
	DbgPrint("Interpret PatchGuard InitialzieContext %d times\n", count);
}

void PrintfRecoverCount(ULONG64 addr)
{
	DbgPrint("Recover addr  %p \n", addr);
}

void DriverUnload(PDRIVER_OBJECT pDrvObject)
{
	pDrvObject;
	DbgPrint("driver unload succsess\n");
}


