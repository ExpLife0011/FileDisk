#include <ntifs.h>
#include "MiniFilter.h"
#include "function.h"
#include "filedisk.h"
#include "crc32.h"

extern PFLT_FILTER g_FilterHandle;					//���������
extern PFLT_PORT 	g_ServerPort;
extern PFLT_PORT 	g_ClientPort;
extern ULONG		g_filediskAuthority;			//Ȩ��

#define BUFFER_SIZE 1024

/************************************************************************/
/* unicodeString ת char                                                */
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
/* ͨ�ò���ǰ                                                            */
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
/* ͨ�ò�����                                                            */
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
/* Createǰ                                                             */
/************************************************************************/
FLT_PREOP_CALLBACK_STATUS MiniFilterPreCreateCallback(
	PFLT_CALLBACK_DATA Data,
	PCFLT_RELATED_OBJECTS FltObjects,
	PVOID *CompletionContext
	)
{

	ULONG operationDescription;

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


	
	//ӵ�ж�дȨ��
	if (FlagOn(g_filediskAuthority, FILEDISK_WRITE_AUTHORITY))
	{
		KdPrint(("FileDisk MiniFilter: IRP_MJ_CREATE Authority: FILEDISK_WRITE_AUTHORITY\n"));
		return (FLT_PREOP_SUCCESS_WITH_CALLBACK);
	}

	//ӵ�ж�Ȩ��
	if (FlagOn(g_filediskAuthority, FILEDISK_READ_AUTHORITY))
	{
		KdPrint(("FileDisk MiniFilter: IRP_MJ_CREATE Authority: FILEDISK_READ_AUTHORITY\n"));

		if (operationDescription != FILE_OPENED)
		{
			Data->IoStatus.Status = STATUS_MEDIA_WRITE_PROTECTED;		//����д����
			Data->IoStatus.Information = 0;

			KdPrint(("FileDisk MiniFilter: IRP_MJ_CREATE return STATUS_MEDIA_WRITE_PROTECTED\n"));
			return FLT_PREOP_COMPLETE;
		}
	}

	//����
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
/* Create��                                                             */
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
/* readǰ                                                             */
/************************************************************************/
FLT_PREOP_CALLBACK_STATUS MiniFilterPreReadCallback(
	PFLT_CALLBACK_DATA Data,
	PCFLT_RELATED_OBJECTS FltObjects,
	PVOID *CompletionContext
	)
{
	//ӵ�ж�дȨ��
	if (FlagOn(g_filediskAuthority, FILEDISK_WRITE_AUTHORITY))
	{
		KdPrint(("FileDisk MiniFilter: IRP_MJ_WRITE Authority: FILEDISK_WRITE_AUTHORITY\n"));
		return (FLT_PREOP_SUCCESS_WITH_CALLBACK);
	}

	//ӵ�ж�Ȩ��
	if (FlagOn(g_filediskAuthority, FILEDISK_READ_AUTHORITY))
	{
		KdPrint(("FileDisk MiniFilter: IRP_MJ_WRITE Authority: FILEDISK_READ_AUTHORITY\n"));
		return (FLT_PREOP_SUCCESS_WITH_CALLBACK);
	}

	//����
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
/* read��                                                             */
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
/* writeǰ                                                             */
/************************************************************************/
FLT_PREOP_CALLBACK_STATUS MiniFilterPreWriteCallback(
	PFLT_CALLBACK_DATA Data,
	PCFLT_RELATED_OBJECTS FltObjects,
	PVOID *CompletionContext
	)
{
	//ӵ�ж�дȨ��
	if (FlagOn(g_filediskAuthority, FILEDISK_WRITE_AUTHORITY))
	{
		KdPrint(("FileDisk MiniFilter: IRP_MJ_READ Authority: FILEDISK_WRITE_AUTHORITY\n"));
		return (FLT_PREOP_SUCCESS_WITH_CALLBACK);
	}

	//ӵ�ж�Ȩ��
	if (FlagOn(g_filediskAuthority, FILEDISK_READ_AUTHORITY))
	{
		KdPrint(("FileDisk MiniFilter: IRP_MJ_READ Authority: FILEDISK_READ_AUTHORITY\n"));
		Data->IoStatus.Status = STATUS_MEDIA_WRITE_PROTECTED;
		Data->IoStatus.Information = 0;
		return FLT_PREOP_COMPLETE;
	}

	//����
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
/* write��                                                             */
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
	//ж�ػص�����
	FltUnregisterFilter(g_FilterHandle);
	return STATUS_SUCCESS;
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

// 	PFILEDISK_NOTIFICATION		notification;		//����֪ͨӦ�ò����Ϣ
// 	ULONG						replyLength = 0;
// 	LARGE_INTEGER				timeOut = { 0 };
// 
// 
// 	UCHAR						replyBuffer[2048] = { 0 };


	HANDLE						threadHandle;

	PREAD_UDISK_CONTEXT			context = NULL;		//�����̵߳��������


	char devicePath[260] = { 0 };


// 	notification = ExAllocatePoolWithTag(NonPagedPool, sizeof(FILEDISK_NOTIFICATION), FILE_DISK_POOL_TAG);

	status = FltGetDiskDeviceObject(FltObjects->Volume, &DeviceObject);

	if (!NT_SUCCESS(status))
	{
		return STATUS_FLT_DO_NOT_ATTACH;
	}

	KdPrint(("FileDisk: MINI_FILTER deviceTyep=%d\n"), DeviceObject->DeviceType);

	/************************************************************************/
	/* �ж��Ƿ���U�̲���   ��������֪ͨ                                        */
	
	GetDeviceBusType(DeviceObject, &busType);
	if (BusTypeUsb == busType)
	{
		//��U�̲���
		KdPrint(("FileDisk: MiniFilter instance ��U�̲���\n"));

		/************************************************************************/
		/* �����и����̲��� �ж���U������  ���notification                        */
		RtlZeroMemory(volProp, sizeof(volPropBuffer));
		status = FltGetVolumeProperties(FltObjects->Volume,
			volProp,
			sizeof(volPropBuffer),
			&retLen);
		workingName = &volProp->RealDeviceName;


		context = (PREAD_UDISK_CONTEXT)ExAllocatePoolWithTag(NonPagedPool, sizeof(READ_UDISK_CONTEXT), FILE_DISK_POOL_TAG);

		context->deviceName = (PWCH)ExAllocatePoolWithTag(NonPagedPool, 2 * wcslen(workingName->Buffer) + 2, FILE_DISK_POOL_TAG);  //�������ֽ��������0000
		RtlZeroMemory(context->deviceName, 2 * wcslen(workingName->Buffer) + 2);
		
		RtlCopyMemory(context->deviceName, workingName->Buffer, 2 * wcslen(workingName->Buffer));


		//�����߳����ڶ�ȡ���̲�������Ϣ

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
	/************************************************************************/

	//�����ж��豸����		������Լ��������豸 ��
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
				//˵���������Լ��������豸
				if (strstr(devicePath, "\\DEVICE\\FILEDISK\\FILEDISK") != NULL)
				{
					KdPrint(("FileDisk: �󶨴��豸\n"));
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


VOID
ReadUDiskThread(
IN PVOID Context
)
{
	OBJECT_ATTRIBUTES			uDiskOa;
	HANDLE						hUDisk;				//U�̾��
	IO_STATUS_BLOCK				iostatus;
	PUCHAR						buffer = NULL;
	LARGE_INTEGER				fileOffset;			//��ȡ���̵�ƫ��

	PFILEDISK_VERIFY			fileDiskVerify;
	ULONG						verifyCode;

	NTSTATUS					status;

	PFILEDISK_NOTIFICATION		notification;		//����֪ͨӦ�ò����Ϣ
	ULONG						replyLength = 0;

	UNICODE_STRING				DeviceName;
	RtlInitUnicodeString(&DeviceName, ((PREAD_UDISK_CONTEXT)Context)->deviceName);

	KdPrint(("FileDisk UDisk Read Thread DeviceName: %wZ\n", &DeviceName));

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

		fileOffset.QuadPart = (2048 + 10 * 1024 * 2/*10M��С��������	*/) * 512;
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
		ExFreePoolWithTag(((PREAD_UDISK_CONTEXT)Context)->deviceName, FILE_DISK_POOL_TAG);
		ExFreePoolWithTag(Context, FILE_DISK_POOL_TAG);

		notification = ExAllocatePoolWithTag(NonPagedPool, sizeof(FILEDISK_NOTIFICATION), FILE_DISK_POOL_TAG);

		//У��ṹ��������Ƿ�ı��  crc

		fileDiskVerify = (PFILEDISK_VERIFY)buffer;
		verifyCode = crc32(fileDiskVerify->code, 508);

		if (verifyCode == fileDiskVerify->verifyCode)
		{
			notification->isSpecial = 1;
			KdPrint(("Filedisk �����Ϊ�ض���U��\n"));
		}
		else
		{
			notification->isSpecial = 0;
			KdPrint(("FileDisk �����Ϊ��ͨ��U��\n"));
		}

		notification->isSpecial = 1;
		notification->fileDiskAuthority = 0;
		notification->offset.QuadPart = 0;
		notification->storageSize.QuadPart = 0;

		status = FltSendMessage(g_FilterHandle,
			&g_ClientPort,
			notification,
			sizeof(FILEDISK_NOTIFICATION),
			NULL,							//	����Ӧ�ò㷢��������Ϣ
			&replyLength,
			NULL
			);

		if (NT_SUCCESS(status))
		{
			//ͨ�����ص�����Ȩ��
			// 			g_filediskAuthority = (PFILEDISK_REPLY)notification->fileDiskAuthority;
			KdPrint(("Filedisk MiniFilter: Ӧ�ò㴫������Ȩ��Ϊ��%d\n", g_filediskAuthority));
		}
		else
		{
			KdPrint(("FileDisk MiniFilter: �����㷢����Ϣʧ�ܣ�%08x\n", status));
		}

}