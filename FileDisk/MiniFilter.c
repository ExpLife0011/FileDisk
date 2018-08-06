#include <ntifs.h>
#include <ntstrsafe.h>
#include "MiniFilter.h"
#include "function.h"
#include "filedisk.h"
#include "crc32.h"

extern PFLT_FILTER g_FilterHandle;					//过滤器句柄
extern PFLT_PORT 	g_ServerPort;
extern PFLT_PORT 	g_ClientPort;
extern ULONG		g_filediskAuthority;			//权限

#define BUFFER_SIZE 1024

/************************************************************************/
/* unicodeString 转 char                                                */
/************************************************************************/
BOOLEAN FDUnicodeStringToChar(PUNICODE_STRING UniName, char Name[])
{
	ANSI_STRING	AnsiName;
	NTSTATUS	ntstatus;
	char*		nameptr;

	__try {
		ntstatus = RtlUnicodeStringToAnsiString(&AnsiName, UniName, TRUE);

		if (AnsiName.Length < 260) {
			nameptr = (PCHAR)AnsiName.Buffer;
			//Convert into upper case and copy to buffer
			strcpy(Name, _strupr(nameptr));
			DbgPrint("FileDisk:FDUnicodeStringToChar : %s\n", Name);
		}
		RtlFreeAnsiString(&AnsiName);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		DbgPrint("FileDisk:FDUnicodeStringToChar EXCEPTION_EXECUTE_HANDLER\n");
		return FALSE;
	}
	return TRUE;
}


/************************************************************************/
/* 通用操作前                                                            */
/************************************************************************/
FLT_PREOP_CALLBACK_STATUS MiniFilterCommonPreOperationCallback(
	PFLT_CALLBACK_DATA Data,
	PCFLT_RELATED_OBJECTS FltObjects,
	PVOID *CompletionContext
	)
{
	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);
	return (FLT_PREOP_SUCCESS_WITH_CALLBACK);
}

/************************************************************************/
/* 通用操作后                                                            */
/************************************************************************/
FLT_POSTOP_CALLBACK_STATUS MiniFilterCommonPostOperationCallback(
	PFLT_CALLBACK_DATA Data,
	PCFLT_RELATED_OBJECTS FltObjects,
	PVOID CompletionContext,
	FLT_POST_OPERATION_FLAGS Flags
	)
{
	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(Flags);
	return (FLT_POSTOP_FINISHED_PROCESSING);
}


/************************************************************************/
/* Create前                                                             */
/************************************************************************/
FLT_PREOP_CALLBACK_STATUS MiniFilterPreCreateCallback(
	PFLT_CALLBACK_DATA Data,
	PCFLT_RELATED_OBJECTS FltObjects,
	PVOID *CompletionContext
	)
{

	ULONG operationDescription;
	PVOLUME_CONTEXT volCtx = NULL;
	NTSTATUS status;

	try
	{
		status = FltGetVolumeContext(FltObjects->Filter,
			FltObjects->Volume,
			&volCtx);

		if (!NT_SUCCESS(status)) 
		{

			leave;
		}

		if (volCtx->is10MVolume)
		{
			Data->IoStatus.Status = STATUS_MEDIA_WRITE_PROTECTED;
			Data->IoStatus.Information = 0;
			return FLT_PREOP_COMPLETE;
		}
	}
	finally
	{

	}

	operationDescription = ((Data->Iopb->Parameters.Create.Options >> 24) & 0x000000FF);
	/*
	FILE_CREATED

	FILE_OPENED

	FILE_OVERWRITTEN

	FILE_SUPERSEDED

	FILE_EXISTS

	FILE_DOES_NOT_EXIST
	*/

	KdPrint(("FileDisk MiniFilter: IRP_MJ_CREATE operationDescription=%d\n", operationDescription));


	
	//拥有读写权限
	if (FlagOn(g_filediskAuthority, FILEDISK_WRITE_AUTHORITY))
	{
		KdPrint(("FileDisk MiniFilter: IRP_MJ_CREATE Authority: FILEDISK_WRITE_AUTHORITY\n"));
		return (FLT_PREOP_SUCCESS_WITH_CALLBACK);
	}

	//拥有读权限
	if (FlagOn(g_filediskAuthority, FILEDISK_READ_AUTHORITY))
	{
		KdPrint(("FileDisk MiniFilter: IRP_MJ_CREATE Authority: FILEDISK_READ_AUTHORITY\n"));

		if (operationDescription != FILE_OPENED)
		{
			Data->IoStatus.Status = STATUS_MEDIA_WRITE_PROTECTED;		//磁盘写保护
			Data->IoStatus.Information = 0;

			KdPrint(("FileDisk MiniFilter: IRP_MJ_CREATE return STATUS_MEDIA_WRITE_PROTECTED\n"));
			return FLT_PREOP_COMPLETE;
		}
	}

	//禁用
	if (g_filediskAuthority == FILEDISK_NONE_AUTHORITY)
	{
		KdPrint(("FileDisk MiniFilter: IRP_MJ_CREATE Authority: FILEDISK_READ_AUTHORITY\n"));
		Data->IoStatus.Status = STATUS_MEDIA_WRITE_PROTECTED;
		Data->IoStatus.Information = 0;
		return FLT_PREOP_COMPLETE;
	}

	return (FLT_PREOP_SUCCESS_WITH_CALLBACK);
}

/************************************************************************/
/* Create后                                                             */
/************************************************************************/
FLT_POSTOP_CALLBACK_STATUS MiniFilterPostCreateCallback(
	PFLT_CALLBACK_DATA Data,
	PCFLT_RELATED_OBJECTS FltObjects,
	PVOID CompletionContext,
	FLT_POST_OPERATION_FLAGS Flags
	)
{
	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(Flags);
	return (FLT_POSTOP_FINISHED_PROCESSING);
}


/************************************************************************/
/* read前                                                             */
/************************************************************************/
FLT_PREOP_CALLBACK_STATUS MiniFilterPreReadCallback(
	PFLT_CALLBACK_DATA Data,
	PCFLT_RELATED_OBJECTS FltObjects,
	PVOID *CompletionContext
	)
{
	//拥有读写权限
	if (FlagOn(g_filediskAuthority, FILEDISK_WRITE_AUTHORITY))
	{
		KdPrint(("FileDisk MiniFilter: IRP_MJ_WRITE Authority: FILEDISK_WRITE_AUTHORITY\n"));
		return (FLT_PREOP_SUCCESS_WITH_CALLBACK);
	}

	//拥有读权限
	if (FlagOn(g_filediskAuthority, FILEDISK_READ_AUTHORITY))
	{
		KdPrint(("FileDisk MiniFilter: IRP_MJ_WRITE Authority: FILEDISK_READ_AUTHORITY\n"));
		return (FLT_PREOP_SUCCESS_WITH_CALLBACK);
	}

	//禁用
	if (g_filediskAuthority == FILEDISK_NONE_AUTHORITY)
	{
		KdPrint(("FileDisk MiniFilter: IRP_MJ_WRITE Authority: FILEDISK_NONE_AUTHORITY\n"));
		Data->IoStatus.Status = STATUS_MEDIA_WRITE_PROTECTED;
		Data->IoStatus.Information = 0;
		return FLT_PREOP_COMPLETE;
	}

	return (FLT_PREOP_SUCCESS_WITH_CALLBACK);
}

/************************************************************************/
/* read后                                                             */
/************************************************************************/
FLT_POSTOP_CALLBACK_STATUS MiniFilterPostReadCallback(
	PFLT_CALLBACK_DATA Data,
	PCFLT_RELATED_OBJECTS FltObjects,
	PVOID CompletionContext,
	FLT_POST_OPERATION_FLAGS Flags
	)
{
	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(Flags);
	return (FLT_POSTOP_FINISHED_PROCESSING);
}


/************************************************************************/
/* write前                                                             */
/************************************************************************/
FLT_PREOP_CALLBACK_STATUS MiniFilterPreWriteCallback(
	PFLT_CALLBACK_DATA Data,
	PCFLT_RELATED_OBJECTS FltObjects,
	PVOID *CompletionContext
	)
{
	//拥有读写权限
	if (FlagOn(g_filediskAuthority, FILEDISK_WRITE_AUTHORITY))
	{
		KdPrint(("FileDisk MiniFilter: IRP_MJ_READ Authority: FILEDISK_WRITE_AUTHORITY\n"));
		return (FLT_PREOP_SUCCESS_WITH_CALLBACK);
	}

	//拥有读权限
	if (FlagOn(g_filediskAuthority, FILEDISK_READ_AUTHORITY))
	{
		KdPrint(("FileDisk MiniFilter: IRP_MJ_READ Authority: FILEDISK_READ_AUTHORITY\n"));
		Data->IoStatus.Status = STATUS_MEDIA_WRITE_PROTECTED;
		Data->IoStatus.Information = 0;
		return FLT_PREOP_COMPLETE;
	}

	//禁用
	if ( g_filediskAuthority == FILEDISK_NONE_AUTHORITY )
	{
		KdPrint(("FileDisk MiniFilter: IRP_MJ_READ Authority: FILEDISK_NONE_AUTHORITY\n"));
		Data->IoStatus.Status = STATUS_MEDIA_WRITE_PROTECTED;
		Data->IoStatus.Information = 0;
		return FLT_PREOP_COMPLETE;
	}

	return (FLT_PREOP_SUCCESS_WITH_CALLBACK);
}

/************************************************************************/
/* write后                                                             */
/************************************************************************/
FLT_POSTOP_CALLBACK_STATUS MiniFilterPostWriteCallback(
	PFLT_CALLBACK_DATA Data,
PCFLT_RELATED_OBJECTS FltObjects,
PVOID CompletionContext,
FLT_POST_OPERATION_FLAGS Flags
)
{
	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(Flags);
	return (FLT_POSTOP_FINISHED_PROCESSING);
}



FLT_PREOP_CALLBACK_STATUS MiniFilterPreShutdownCallback(
	PFLT_CALLBACK_DATA Data,
	PCFLT_RELATED_OBJECTS FltObjects,
	PVOID *CompletionContext
	)
{
	return (FLT_PREOP_SUCCESS_NO_CALLBACK);
}


NTSTATUS
MiniFilterUnload(
_In_ FLT_FILTER_UNLOAD_FLAGS Flags
)
{
	//卸载回调函数
	FltUnregisterFilter(g_FilterHandle);
	return STATUS_SUCCESS;
}

#define MAX_PATH 256

//输入\\??\\c:-->\\device\\\harddiskvolume1
//LinkTarget.Buffer注意要释放

NTSTATUS QuerySymbolicLink(
	IN PUNICODE_STRING SymbolicLinkName,
	OUT PUNICODE_STRING LinkTarget
	)
{
	OBJECT_ATTRIBUTES   oa = { 0 };
	NTSTATUS            status = 0;
	HANDLE              handle = NULL;

	InitializeObjectAttributes(
		&oa,
		SymbolicLinkName,
		OBJ_CASE_INSENSITIVE,
		0,
		0);

	status = ZwOpenSymbolicLinkObject(&handle, GENERIC_READ, &oa);
	if (!NT_SUCCESS(status))
	{
		return status;
	}

	LinkTarget->MaximumLength = MAX_PATH*sizeof(WCHAR);
	LinkTarget->Length = 0;
	LinkTarget->Buffer = ExAllocatePoolWithTag(PagedPool, LinkTarget->MaximumLength, 'SOD');
	if (!LinkTarget->Buffer)
	{
		ZwClose(handle);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	RtlZeroMemory(LinkTarget->Buffer, LinkTarget->MaximumLength);

	status = ZwQuerySymbolicLinkObject(handle, LinkTarget, NULL);
	ZwClose(handle);

	if (!NT_SUCCESS(status))
	{
		ExFreePool(LinkTarget->Buffer);
	}

	return status;
}

//输入\\Device\\harddiskvolume1
//输出C:
//DosName.Buffer的内存记得释放

NTSTATUS
MyRtlVolumeDeviceToDosName(
IN PUNICODE_STRING DeviceName,
OUT PUNICODE_STRING DosName
)

/*++

Routine Description:

This routine returns a valid DOS path for the given device object.
This caller of this routine must call ExFreePool on DosName->Buffer
when it is no longer needed.

Arguments:

VolumeDeviceObject - Supplies the volume device object.
DosName - Returns the DOS name for the volume
Return Value:

NTSTATUS

--*/

{
	NTSTATUS                status = 0;
	UNICODE_STRING          driveLetterName = { 0 };
	WCHAR                   driveLetterNameBuf[128] = { 0 };
	WCHAR                   c = L'\0';
	WCHAR                   DriLetter[3] = { 0 };
	UNICODE_STRING          linkTarget = { 0 };

	for (c = L'A'; c <= L'Z'; c++)
	{
		RtlInitEmptyUnicodeString(&driveLetterName, driveLetterNameBuf, sizeof(driveLetterNameBuf));
		RtlAppendUnicodeToString(&driveLetterName, L"\\??\\");
		DriLetter[0] = c;
		DriLetter[1] = L':';
		DriLetter[2] = 0;
		RtlAppendUnicodeToString(&driveLetterName, DriLetter);

		status = QuerySymbolicLink(&driveLetterName, &linkTarget);
		if (!NT_SUCCESS(status))
		{
			continue;
		}

		if (RtlEqualUnicodeString(&linkTarget, DeviceName, TRUE))
		{
			ExFreePool(linkTarget.Buffer);
			break;
		}

		ExFreePool(linkTarget.Buffer);
	}

	if (c <= L'Z')
	{
		DosName->Buffer = ExAllocatePoolWithTag(PagedPool, 3 * sizeof(WCHAR), FILE_DISK_POOL_TAG);
		if (!DosName->Buffer)
		{
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		DosName->MaximumLength = 6;
		DosName->Length = 4;
		*DosName->Buffer = c;
		*(DosName->Buffer + 1) = ':';
		*(DosName->Buffer + 2) = 0;

		//DosName->Buffer 这个用完要清理内存
		return STATUS_SUCCESS;
	}

	return status;
}



// 输入 \\Device\\harddiskvolume1
// 输出 0 or 1 or 2
// 通过设备名获取物理磁盘号

#define MAX_DISK_NUM			10
#define MAX_PARTITION_NUM		10

NTSTATUS
MyRtlVolumeDeviceGetPhysicalNumber(
IN PUNICODE_STRING DeviceName,
OUT PULONG PhysicalNumber
)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	ULONG partitionNo = 0;
	ULONG harddiskNo = 0;
	BOOLEAN	isFind = FALSE;

	WCHAR wc_symbolicLink[512] = {0};
	UNICODE_STRING symbolicLink;
	UNICODE_STRING linkTarget = {0};

	RtlInitEmptyUnicodeString(&symbolicLink, wc_symbolicLink, 512 * sizeof(WCHAR));

	
	for (harddiskNo = 0; harddiskNo < MAX_DISK_NUM; harddiskNo++)
	{
		for (partitionNo = 0; partitionNo < MAX_PARTITION_NUM; partitionNo++)
		{
			status = RtlStringCbPrintfW(symbolicLink.Buffer,
				512 * sizeof(WCHAR),
				L"\\??\\Harddisk%dPartition%d",
				harddiskNo,
				partitionNo);
			symbolicLink.Length = wcslen(symbolicLink.Buffer) * sizeof(WCHAR);

// 			KdPrint(("FileDisk: 遍历的符号链接：%wZ\n", &symbolicLink));

			status = QuerySymbolicLink(&symbolicLink, &linkTarget);
			if (!NT_SUCCESS(status))
			{
				continue;
			}

			if (RtlEqualUnicodeString(&linkTarget, DeviceName, TRUE))
			{
				isFind = TRUE;
				ExFreePool(linkTarget.Buffer);
				KdPrint(("FileDisk: 该磁盘的物理号为：%d\n", harddiskNo));
				break;
			}
		}

		if (isFind)
		{
			status = STATUS_SUCCESS;
			break;
		}
	}

	*PhysicalNumber = harddiskNo;
	return status;
}


NTSTATUS
MiniFilterInstanceSetup(
_In_ PCFLT_RELATED_OBJECTS FltObjects,
_In_ FLT_INSTANCE_SETUP_FLAGS Flags,
_In_ DEVICE_TYPE VolumeDeviceType,
_In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
)
{
	PDEVICE_OBJECT DeviceObject;
	NTSTATUS status;
	BYTE busType;

	ULONG retLen;
	UCHAR volPropBuffer[sizeof(FLT_VOLUME_PROPERTIES) + 512];
	PFLT_VOLUME_PROPERTIES volProp = (PFLT_VOLUME_PROPERTIES)volPropBuffer;
	PUNICODE_STRING workingName;

	// 	PFILEDISK_NOTIFICATION		notification;		//驱动通知应用层的消息
	// 	ULONG						replyLength = 0;
	// 	LARGE_INTEGER				timeOut = { 0 };
	// 
	// 
	// 	UCHAR						replyBuffer[2048] = { 0 };


	HANDLE						threadHandle;

	PREAD_UDISK_CONTEXT			context = NULL;		//传入线程的相关数据
	UNICODE_STRING				DosName = {0};			//通过设备名称获取的盘符

	ULONG						harddiskNo = 0;			//物理磁盘号
	PVOLUME_CONTEXT				ctx = NULL;


	char devicePath[260] = { 0 };


	// 	notification = ExAllocatePoolWithTag(NonPagedPool, sizeof(FILEDISK_NOTIFICATION), FILE_DISK_POOL_TAG);

	status = FltGetDiskDeviceObject(FltObjects->Volume, &DeviceObject);
// 	status = FltGetDeviceObject(FltObjects->Volume, &DeviceObject);

	if (!NT_SUCCESS(status))
	{
		return STATUS_UNSUCCESSFUL;
	}

	KdPrint(("FileDisk: MINI_FILTER deviceTyep=%d\n"), DeviceObject->DeviceType);

	/************************************************************************/
	/* 判断是否有U盘插入   插入立即通知                                        */

	GetDeviceBusType(DeviceObject, &busType);
	if (BusTypeUsb == busType)
	{
		//有U盘插入
		KdPrint(("FileDisk: MiniFilter instance 有U盘插入\n"));

		/************************************************************************/
		/* 这里有个读盘操作 判断是U盘类型  填充notification                        */
		RtlZeroMemory(volProp, sizeof(volPropBuffer));
		status = FltGetVolumeProperties(FltObjects->Volume,
			volProp,
			sizeof(volPropBuffer),
			&retLen);
		workingName = &volProp->RealDeviceName;

		//过滤一个设备卷

// 		if (FDUnicodeStringToChar(workingName, devicePath))
// 		{
// 			if (strstr(devicePath, "VOLUME") != NULL)
// 			{
// 				//说明这是一个卷设备
// 				KdPrint(("FileDisk: 这是一个设备卷\n"));
// 				return STATUS_UNSUCCESSFUL;
// 			}
// 		}

		//获取盘符
		status = MyRtlVolumeDeviceToDosName(workingName, &DosName);

		MyRtlVolumeDeviceGetPhysicalNumber(workingName, &harddiskNo);

		if (NT_SUCCESS(status))
		{
			context = (PREAD_UDISK_CONTEXT)ExAllocatePoolWithTag(NonPagedPool, sizeof(READ_UDISK_CONTEXT), FILE_DISK_POOL_TAG);

			context->deviceName = (PWCH)ExAllocatePoolWithTag(NonPagedPool, 2 * wcslen(DosName.Buffer) + 2, FILE_DISK_POOL_TAG);  //多两个字节用于填充0000
			RtlZeroMemory(context->deviceName, 2 * wcslen(DosName.Buffer) + 2);

			RtlCopyMemory(context->deviceName, DosName.Buffer, 2 * wcslen(DosName.Buffer));
			context->hardDiskNo = harddiskNo;

			ExFreePoolWithTag(DosName.Buffer, FILE_DISK_POOL_TAG);



			try
			{
				status = FltAllocateContext(FltObjects->Filter,
					FLT_VOLUME_CONTEXT,
					sizeof(VOLUME_CONTEXT),
					NonPagedPool,
					&ctx);

				if (!NT_SUCCESS(status)) {

					//
					//  We could not allocate a context, quit now
					//

					leave;
				}
				RtlZeroMemory(ctx, sizeof(VOLUME_CONTEXT));

				if (Is10MVolume(harddiskNo))
				{
					ctx->is10MVolume = 1;
				}
				else
				{
					ctx->is10MVolume = 0;
				}

			}
			finally
			{

			}

			//创建线程用于读取磁盘并发送消息

			status = PsCreateSystemThread(
				&threadHandle,
				(ACCESS_MASK)0L,
				NULL,
				NULL,
				NULL,
				ReadUDiskThread,				
				context
				);
		}

 	}
	/************************************************************************/

	//首先判断设备类型		如果是自己创建的设备 绑定
	if (FILE_DEVICE_DISK == DeviceObject->DeviceType)
	{
		RtlZeroMemory(volProp, sizeof(volPropBuffer));
		status = FltGetVolumeProperties(FltObjects->Volume,
			volProp,
			sizeof(volPropBuffer),
			&retLen);


		if (volProp->RealDeviceName.Length > 0)
		{
			workingName = &volProp->RealDeviceName;

			KdPrint(("FileDisk: MINI_FILTER realDeviceName: %wZ\n", workingName));

			if (FDUnicodeStringToChar(workingName, devicePath))
			{
				//说明是我们自己创建的设备
				if (strstr(devicePath, "\\DEVICE\\FILEDISK\\FILEDISK") != NULL)
				{
					KdPrint(("FileDisk: 绑定此设备\n"));
					return STATUS_SUCCESS;
				}
			}

		}

	}
	else
	{
		return STATUS_FLT_DO_NOT_ATTACH;
	}


// 	ExFreePoolWithTag(notification, FILE_DISK_POOL_TAG);

	return STATUS_FLT_DO_NOT_ATTACH;
}


NTSTATUS
MiniFilterInstanceQueryTeardown(
_In_ PCFLT_RELATED_OBJECTS FltObjects,
_In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
)
{
	return STATUS_SUCCESS;
}


BOOLEAN
Is10MVolume(
IN ULONG hardDiskNo
)
{
	UNICODE_STRING				DeviceName = { 0 };
	WCHAR						wc_DeviceName[512] = { 0 };
	OBJECT_ATTRIBUTES			uDiskOa;
	HANDLE						hUDisk;				//U盘句柄
	IO_STATUS_BLOCK				iostatus;
	PUCHAR						buffer = NULL;
	LARGE_INTEGER				fileOffset;			//读取磁盘的偏移
	NTSTATUS					status;
	LARGE_INTEGER				partitionSize = {0};
	ULONG						partitionSectors;

	RtlInitEmptyUnicodeString(&DeviceName, wc_DeviceName, 512 * sizeof(WCHAR));
	RtlStringCbPrintfW(DeviceName.Buffer, 512 * sizeof(WCHAR), L"\\??\\physicaldrive%d", hardDiskNo);
	DeviceName.Length = wcslen(DeviceName.Buffer) * 2;

	if (hardDiskNo != 0)
	{
		// \??\physicaldrive0 是系统所在的盘，如果为0的话，则该盘不是指定的u盘

		InitializeObjectAttributes(&uDiskOa,
			&DeviceName,
			OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
			NULL,
			NULL);

		status = ZwCreateFile(&hUDisk,
			GENERIC_READ,
			&uDiskOa,
			&iostatus,
			NULL,
			FILE_ATTRIBUTE_NORMAL,
			FILE_SHARE_READ,
			FILE_OPEN,
			FILE_NON_DIRECTORY_FILE |
			FILE_RANDOM_ACCESS |
			FILE_NO_INTERMEDIATE_BUFFERING |
			FILE_SYNCHRONOUS_IO_NONALERT |
			FILE_WRITE_THROUGH,
			NULL,
			0
			);


		if (!NT_SUCCESS(status))
		{
			KdPrint(("FileDisk ReadUdiskThread CreateFile error, errCode:%08x\n", status));
			return FALSE;
		}

		fileOffset.QuadPart = 0;
		buffer = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, 512, FILE_DISK_POOL_TAG);
		status = ZwReadFile(
			hUDisk,
			NULL,
			NULL,
			NULL,
			&iostatus,
			buffer,
			512,
			&fileOffset,
			NULL);

		if (!NT_SUCCESS(status))
		{
			ZwClose(hUDisk);
			return FALSE;
		}
		ZwClose(hUDisk);

		partitionSectors = *(DWORD *)&buffer[0x1CA];
		partitionSize.QuadPart = partitionSectors * 512;

		if (partitionSectors == 0x5000)
		{
			return TRUE;
		}
		else
		{
			return FALSE;
		}
	}
	else
	{
		return FALSE;
	}

}

VOID
ReadUDiskThread(
IN PVOID Context
)
{
	OBJECT_ATTRIBUTES			uDiskOa;
	HANDLE						hUDisk;				//U盘句柄
	IO_STATUS_BLOCK				iostatus;
	PUCHAR						buffer = NULL;
	LARGE_INTEGER				fileOffset;			//读取磁盘的偏移
	ULONGLONG					diskSize = 0;			//磁盘大小

	PFILEDISK_VERIFY			fileDiskVerify;
	ULONG						verifyCode;

	NTSTATUS					status;

	PFILEDISK_NOTIFICATION		notification;		//驱动通知应用层的消息
	ULONG						replyLength = 0;

	UNICODE_STRING				DeviceName = {0};
	WCHAR						wc_DeviceName[512] = { 0 };

	ULONG						hardDiskNo = 0;

	RtlInitUnicodeString(&DeviceName, ((PREAD_UDISK_CONTEXT)Context)->deviceName);
	hardDiskNo = ((PREAD_UDISK_CONTEXT)Context)->hardDiskNo;

	KdPrint(("FileDisk UDisk Read Thread DeviceName: %wZ\n", &DeviceName));
	KdPrint(("FileDisk UDisk Read Thread hardDiskNo: %d\n", hardDiskNo));

	RtlInitEmptyUnicodeString(&DeviceName, wc_DeviceName, 512 * sizeof(WCHAR));
	RtlStringCbPrintfW(DeviceName.Buffer, 512 * sizeof(WCHAR), L"\\??\\physicaldrive%d", hardDiskNo);
	DeviceName.Length = wcslen(DeviceName.Buffer) * 2;

	notification = ExAllocatePoolWithTag(NonPagedPool, sizeof(FILEDISK_NOTIFICATION), FILE_DISK_POOL_TAG);

	if (hardDiskNo != 0)
	{
		// \??\physicaldrive0 是系统所在的盘，如果为0的话，则该盘不是指定的u盘

		InitializeObjectAttributes(&uDiskOa,
			&DeviceName,
			OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
			NULL,
			NULL);

		status = ZwCreateFile(&hUDisk,
			GENERIC_READ,
			&uDiskOa,
			&iostatus,
			NULL,
			FILE_ATTRIBUTE_NORMAL,
			FILE_SHARE_READ,
			FILE_OPEN,
			FILE_NON_DIRECTORY_FILE |
			FILE_RANDOM_ACCESS |
			FILE_NO_INTERMEDIATE_BUFFERING |
			FILE_SYNCHRONOUS_IO_NONALERT |
			FILE_WRITE_THROUGH,
			NULL,
			0
			);


		if (!NT_SUCCESS(status))
		{
			KdPrint(("FileDisk ReadUdiskThread CreateFile error, errCode:%08x\n", status));
			return;
		}

		fileOffset.QuadPart = (2048 + 10 * 1024 * 2/*10M大小的扇区数	*/) * 512;
		buffer = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, 512, FILE_DISK_POOL_TAG);
		status = ZwReadFile(
			hUDisk,
			NULL,
			NULL,
			NULL,
			&iostatus,
			buffer,
			512,
			&fileOffset,
			NULL);

		if (!NT_SUCCESS(status))
		{
			KdPrint(("FileDisk ReadUdiskThread readfile error, errCode:%08x\n", status));
			ExFreePoolWithTag(((PREAD_UDISK_CONTEXT)Context)->deviceName, FILE_DISK_POOL_TAG);
			ExFreePoolWithTag(Context, FILE_DISK_POOL_TAG);
			ZwClose(hUDisk);
			return;
		}
		ZwClose(hUDisk);

		//校验结构体的数据是否改变过  crc

		fileDiskVerify = (PFILEDISK_VERIFY)buffer;
		diskSize = *(ULONGLONG *)&fileDiskVerify->diskSize;
		verifyCode = crc32(fileDiskVerify->code, 508);

		if (verifyCode == fileDiskVerify->verifyCode)
		{
			notification->isSpecial = 1;
			KdPrint(("Filedisk 插入的为特定的U盘\n"));
		}
		else
		{
			notification->isSpecial = 0;
			KdPrint(("FileDisk 插入的为普通的U盘\n"));
		}

	}
	else
	{
		notification->isSpecial = 0;
	}



	notification->fileDiskAuthority = 0;
	notification->offset.QuadPart = 0;
	notification->storageSize.QuadPart = diskSize;
	KdPrint(("FileDisk: 磁盘的大小为：%lld\n", diskSize));
	RtlCopyMemory(notification->Contents, ((PREAD_UDISK_CONTEXT)Context)->deviceName, wcslen(((PREAD_UDISK_CONTEXT)Context)->deviceName));

	ExFreePoolWithTag(((PREAD_UDISK_CONTEXT)Context)->deviceName, FILE_DISK_POOL_TAG);
	ExFreePoolWithTag(Context, FILE_DISK_POOL_TAG);

	status = FltSendMessage(g_FilterHandle,
		&g_ClientPort,
		notification,
		sizeof(FILEDISK_NOTIFICATION),
		NULL,							//	接收应用层发过来的消息
		&replyLength,
		NULL
		);

	if (NT_SUCCESS(status))
	{
		//通过返回的设置权限
		// 			g_filediskAuthority = (PFILEDISK_REPLY)notification->fileDiskAuthority;
		KdPrint(("Filedisk MiniFilter: 应用层传过来的权限为：%d\n", g_filediskAuthority));
	}
	else
	{
		KdPrint(("FileDisk MiniFilter: 驱动层发送消息失败：%08x\n", status));
	}

}


VOID
CleanupVolumeContext(
_In_ PFLT_CONTEXT Context,
_In_ FLT_CONTEXT_TYPE ContextType
)
/*++

Routine Description:

The given context is being freed.
Free the allocated name buffer if there one.

Arguments:

Context - The context being freed

ContextType - The type of context this is

Return Value:

None

--*/
{
	PVOLUME_CONTEXT ctx = Context;

	PAGED_CODE();

	UNREFERENCED_PARAMETER(ContextType);

	FLT_ASSERT(ContextType == FLT_VOLUME_CONTEXT);

}