#include "../public/hcdef.h"
#include "../public/hcvirtual.h"
#include "../public/hcprocess.h"
#include "../public/hcstring.h"

PHC_MODULE_INFORMATIONW HCAPI HcInitializeModuleInformationW(DWORD tNameSize, DWORD tPathSize)
{
	PHC_MODULE_INFORMATIONW obj = HcAlloc(sizeof(*obj));

	obj->Name = HcStringAllocW(tNameSize);
	obj->Path = HcStringAllocW(tPathSize);
	obj->Size = 0;
	obj->Base = 0;

	return obj;
}

VOID HCAPI HcDestroyModuleInformationW(PHC_MODULE_INFORMATIONW o)
{
	HcFree(o->Name);
	HcFree(o->Path);
	HcFree(o);
}
PHC_PROCESS_INFORMATION_EXW HCAPI HcInitializeProcessInformationExW(DWORD tNameSize)
{
	PHC_PROCESS_INFORMATION_EXW obj = HcAlloc(sizeof(*obj));

	obj->MainModule = HcInitializeModuleInformationW(tNameSize, tNameSize);
	obj->Name = HcStringAllocW(tNameSize);
	obj->Id = 0;
	obj->CanAccess = 0;

	return obj;
}

VOID HCAPI HcDestroyProcessInformationExW(PHC_PROCESS_INFORMATION_EXW o)
{
	HcFree(o->Name);
	HcDestroyModuleInformationW(o->MainModule);
	HcFree(o);
}

PHC_PROCESS_INFORMATIONW HCAPI HcInitializeProcessInformationW(DWORD tNameSize)
{
	PHC_PROCESS_INFORMATIONW obj;

	obj = HcAlloc(sizeof(*obj));
	obj->Name = HcStringAllocW(tNameSize);
	obj->Id = 0;

	return obj;
}

VOID HCAPI HcDestroyProcessInformationW(PHC_PROCESS_INFORMATIONW o)
{
	HcFree(o->Name);
	HcFree(o);
}