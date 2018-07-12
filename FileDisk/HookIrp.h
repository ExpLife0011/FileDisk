#ifndef _HOOKIRP_H_
#define _HOOKIRP_H_

#include <ntddk.h>

#define HOOK_DRIVER_NAME     L"\\Driver\\Disk" 

#ifdef __cplusplus
extern "C"
{
#endif

//
// -- HOOK DISK.SYS 回调例程
//
BOOLEAN
	HookIRP_Install(VOID);

//
// -- HOOK DISK.SYS 回调例程
//
BOOLEAN
	HookIRP_Uninstall(VOID);

NTSTATUS
HookIrp_DispatchPnpDisk(
IN PDEVICE_OBJECT DeviceObject,
IN PIRP Irp
);
#ifdef __cplusplus
}
#endif

#endif // !_HOOKIRP_H_
