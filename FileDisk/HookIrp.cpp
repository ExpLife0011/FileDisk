#include "HookIrp.h"


/************************************************************************/
/* 目前弃用，可能有多次提示插入的情况                                      */
/************************************************************************/

// extern POBJECT_TYPE *IoDriverObjectType;
// 
// #ifdef __cplusplus
// extern "C"
// {
// #endif
// 
// 	typedef NTSTATUS(*DISPATCH_ENTRY)(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
// 
// 	DISPATCH_ENTRY Hook_Old_Entry_DispatchPnp_Disk = NULL;
// 	/************************************************************************/
// 	/*        未公开函数                                                     */
// 
// 	NTKERNELAPI
// 		NTSTATUS
// 		NTAPI
// 		ObReferenceObjectByName(
// 		IN PUNICODE_STRING	ObjectName,
// 		IN ULONG	 Attributes,
// 		IN PACCESS_STATE	PassedAccessState OPTIONAL,
// 		IN ACCESS_MASK	 DesiredAccess OPTIONAL,
// 		IN POBJECT_TYPE	 ObjectType OPTIONAL,
// 		IN KPROCESSOR_MODE	AccessMode,
// 		IN OUT PVOID	 ParseContext OPTIONAL,
// 		OUT	PVOID	 *Object
// 		);
// 	/************************************************************************/
// 
// 
// NTSTATUS GetDriverObject(IN PWCHAR DeviceName, OUT PDRIVER_OBJECT *DriverObject)
// {
// 	NTSTATUS        Status;
// 	UNICODE_STRING  uDeviceName;
// 	RtlInitUnicodeString(&uDeviceName, DeviceName);
// 
// 	Status = ObReferenceObjectByName(
// 		&uDeviceName,
// 		OBJ_CASE_INSENSITIVE,
// 		NULL,
// 		0,
// 		(POBJECT_TYPE)*IoDriverObjectType,
// 		KernelMode,
// 		NULL,
// 		(PVOID *)DriverObject);
// 
// 	//ObDereferenceObject( *DriverObject );
// 
// 	return Status;
// }
// 
// //////////////////////////////////////////////////////////////////////////
// //////////////////////////////////////////////////////////////////////////
// BOOLEAN
// 	HookIRP_Install(VOID)
// {
// 	NTSTATUS        Status;
// 	PDRIVER_OBJECT  DriverObject = NULL;
// 	KIRQL           Irql;
// 
// 
// 	// -- Hook Disk
// 	Status = GetDriverObject(HOOK_DRIVER_NAME, &DriverObject);
// 	if (!NT_SUCCESS(Status))
// 	{
// 		KdPrint(("HookIRP_Install: GetDeviceObjectEx (Driver\\Disk) error!!\n"));
// 		return FALSE;
// 	}
// 
// 	KeRaiseIrql(HIGH_LEVEL, &Irql);
// 
// 	//hook 即时插拔
// 	Hook_Old_Entry_DispatchPnp_Disk = (DISPATCH_ENTRY)DriverObject->MajorFunction[IRP_MJ_PNP];
// 
// 	if (Hook_Old_Entry_DispatchPnp_Disk)
// 	{
// 		InterlockedExchangePointer((PVOID*)&DriverObject->MajorFunction[IRP_MJ_PNP], (PVOID)HookIrp_DispatchPnpDisk);
// 	}
// 
// 	KeLowerIrql(Irql);
// 
// 	ObfDereferenceObject(DriverObject);
// 	DriverObject = NULL;
// 
// 
// 	return TRUE;
// }
// 
// 
// NTSTATUS HookIrp_DispatchPnpDisk(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
// {
// 	NTSTATUS                   Status = STATUS_UNSUCCESSFUL;
// 	PIO_STACK_LOCATION         IrpSp = NULL;
// 	DVCLOCK_DEVICE_INFO_EX    *DeviceInfo = NULL;
// 	UCHAR IrpMini = 0xFF; //避免使用和 IRP_MN_XXx冲突的初始化值
// 	ULONG sidSize = 0;
// 	IrpSp = IoGetCurrentIrpStackLocation(Irp);
// 
// 	IrpMini = IrpSp->MinorFunction;
// 
// 	KdPrint(("HookIrp_DispatchPnpDisk enter....\n"));
// 
// 	Status = HookIrp_CallPnpDisk(DeviceObject, Irp);
// 	if (NT_SUCCESS(Status))
// 	{
// 		KdPrint(("HookIrp_DispatchPnpDisk:%08x, PID:%08x\n", IrpMini, (ULONG)PsGetCurrentProcessId()));
// 		switch (IrpMini)
// 		{
// 		case  IRP_MN_START_DEVICE:
// 			// -- 从链表中查找磁盘设备信息
// 			DeviceInfo = DistillDvcLockDeviceInfo(DeviceObject, Irp, IRP_DVCLOCK_DISK_READ_WRITE);
// 			if (NULL != DeviceInfo)
// 			{
// 				DvcLockFree(DeviceInfo);
// 				DeviceInfo = NULL;
// 			}
// 			break;
// 		case IRP_MN_REMOVE_DEVICE:
// 			KdPrint(("IRP_MN_REMOVE_DEVICE\n"));
// 			RemoveDvcLockDeviceInfoList(DeviceObject);
// 			break;
// 		default:
// 			break;
// 		}
// 	}
// 	return Status;
// }
// 
// 
// 
// NTSTATUS
// HookIrp_CallPnpDisk(
// IN PDEVICE_OBJECT DeviceObject,
// IN PIRP Irp
// )
// {
// 	return ((DISPATCH_ENTRY)Hook_Old_Entry_DispatchPnp_Disk)(DeviceObject, Irp);
// }
// 
// #ifdef __cplusplus
// }
// #endif