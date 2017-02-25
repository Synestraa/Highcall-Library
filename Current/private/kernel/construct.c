#include <highcall.h>

DECL_EXTERN_API(PHC_MODULE_INFORMATIONW, InitializeModuleInformationW, DWORD tNameSize, DWORD tPathSize)
{
	PHC_MODULE_INFORMATIONW obj = HcAlloc(sizeof(*obj));

	obj->Name = HcStringAllocW(tNameSize);
	obj->Path = HcStringAllocW(tPathSize);

	return obj;
}

DECL_EXTERN_API(VOID, DestroyModuleInformationW, PHC_MODULE_INFORMATIONW o)
{
	HcFree(o->Name);
	HcFree(o->Path);
	HcFree(o);
}

DECL_EXTERN_API(PHC_PROCESS_INFORMATION_EXW, InitializeProcessInformationExW, DWORD tNameSize)
{
	PHC_PROCESS_INFORMATION_EXW obj = HcAlloc(sizeof(*obj));

	obj->MainModule = HcInitializeModuleInformationW(tNameSize, tNameSize);
	obj->Name = HcStringAllocW(tNameSize);

	return obj;
}

DECL_EXTERN_API(VOID, DestroyProcessInformationExW, PHC_PROCESS_INFORMATION_EXW o)
{
	HcFree(o->Name);
	HcDestroyModuleInformationW(o->MainModule);
	HcFree(o);
}

DECL_EXTERN_API(PHC_PROCESS_INFORMATIONW, InitializeProcessInformationW, DWORD tNameSize)
{
	PHC_PROCESS_INFORMATIONW obj;

	obj = HcAlloc(sizeof(*obj));
	obj->Name = HcStringAllocW(tNameSize);

	return obj;
}

DECL_EXTERN_API(VOID, DestroyProcessInformationW, PHC_PROCESS_INFORMATIONW o)
{
	HcFree(o->Name);
	HcFree(o);
}