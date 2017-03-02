#include <highcall.h>

DECL_EXTERN_API(PHC_MODULE_INFORMATIONW, InitializeModuleInformationW, CONST IN DWORD tNameSize, CONST IN DWORD tPathSize)
{
	PHC_MODULE_INFORMATIONW obj = HcAlloc(sizeof(*obj));

	obj->Name = HcStringAllocW(tNameSize);
	obj->Path = HcStringAllocW(tPathSize);

	return obj;
}

DECL_EXTERN_API(VOID, DestroyModuleInformationW, IN PHC_MODULE_INFORMATIONW o)
{
	HcFree(o->Name);
	HcFree(o->Path);
	HcFree(o);
}

DECL_EXTERN_API(PHC_PROCESS_INFORMATION_EXW, InitializeProcessInformationExW, CONST IN DWORD tNameSize)
{
	PHC_PROCESS_INFORMATION_EXW obj = HcAlloc(sizeof(*obj));

	obj->MainModule = HcInitializeModuleInformationW(tNameSize, tNameSize);
	obj->Name = HcStringAllocW(tNameSize);

	return obj;
}

DECL_EXTERN_API(VOID, DestroyProcessInformationExW, IN PHC_PROCESS_INFORMATION_EXW o)
{
	HcFree(o->Name);
	HcDestroyModuleInformationW(o->MainModule);
	HcFree(o);
}

DECL_EXTERN_API(PHC_PROCESS_INFORMATIONW, InitializeProcessInformationW, CONST IN DWORD tNameSize)
{
	PHC_PROCESS_INFORMATIONW obj;

	obj = HcAlloc(sizeof(*obj));
	obj->Name = HcStringAllocW(tNameSize);

	return obj;
}

DECL_EXTERN_API(VOID, DestroyProcessInformationW, IN PHC_PROCESS_INFORMATIONW o)
{
	HcFree(o->Name);
	HcFree(o);
}