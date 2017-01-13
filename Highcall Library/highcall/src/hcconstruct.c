#include "../headers/hcdef.h"
#include "../headers/hcvirtual.h"
#include "../headers/hcprocess.h"

PHC_MODULE_INFORMATIONW HCAPI HcInitializeModuleInformationW(SIZE_T s1, SIZE_T s2)
{
	PHC_MODULE_INFORMATIONW obj = HcAlloc(sizeof(*obj));

	obj->Name = (LPWSTR)HcAlloc(s1 * sizeof(WCHAR) + sizeof(WCHAR));
	obj->Path = (LPWSTR)HcAlloc(s2 * sizeof(WCHAR) + sizeof(WCHAR));
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
PHC_PROCESS_INFORMATION_EXW HCAPI HcInitializeProcessInformationExW(SIZE_T s1)
{
	PHC_PROCESS_INFORMATION_EXW obj = HcAlloc(sizeof(*obj));

	obj->MainModule = HcInitializeModuleInformationW(s1, s1);

	obj->Name = (LPWSTR)HcAlloc(s1 *sizeof(WCHAR) + sizeof(WCHAR));
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

PHC_PROCESS_INFORMATIONW HCAPI HcInitializeProcessInformationW(SIZE_T s1)
{
	PHC_PROCESS_INFORMATIONW obj;

	obj = HcAlloc(sizeof(*obj));
	obj->Name = (LPWSTR)HcAlloc(s1 * sizeof(WCHAR) + sizeof(WCHAR));
	obj->Id = 0;

	return obj;
}

VOID HCAPI HcDestroyProcessInformationW(PHC_PROCESS_INFORMATIONW o)
{
	HcFree(o->Name);
	HcFree(o);
}