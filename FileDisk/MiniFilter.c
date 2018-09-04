#include <ntifs.h>
#include <ntstrsafe.h>
#include "MiniFilter.h"
#include "function.h"
#include "filedisk.h"
#include "crc32.h"

extern PFLT_FILTER g_FilterHandle;					//���������
extern PFLT_PORT 	g_ServerPort;
extern PFLT_PORT 	g_ClientPort;
extern ULONG		g_filediskAuthority;			//Ȩ��
extern ULONG		g_exceptProcessId;
extern ULONG		g_formatting;				//�Ƿ��ڸ�ʽ������
extern ULONG		g_fileAudit;				//�ļ����
extern LIST_ENTRY   gConnList;
extern KSPIN_LOCK   gConnListLock;
extern KEVENT       gWorkerEvent;
extern PUNICODE_STRING ScannedExtensions;
extern ULONG ScannedExtensionCount;
extern PWCHAR		g_backFilePath;
extern PWCHAR		g_scannedExtensions;


#define BUFFER_SIZE 1024
//
// �ļ����ڴ��
//
NPAGED_LOOKASIDE_LIST  g_FileNamePool;       //file name pool


NTKERNELAPI
UCHAR * PsGetProcessImageFileName(__in PEPROCESS Process);

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
			// 			DbgPrint("FileDisk:FDUnicodeStringToChar : %s\n", Name);
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
	PVOLUME_CONTEXT ctx = NULL;

	ULONG operationDescription;

	NTSTATUS status;


	status = FltGetVolumeContext(
		FltObjects->Filter,
		FltObjects->Volume,
		&ctx);

	if (NT_SUCCESS(status))
	{
		KdPrint(("FileDisk: 10M�ռ��������ID��%d\n", (ULONG)PsGetCurrentProcessId()));
		if (g_formatting || (ULONG)PsGetCurrentProcessId() < 5) //0--4���̷Ź�
		{
			KdPrint(("FileDisk: Create10M�ռ�Ź�\n"));
			return (FLT_PREOP_SUCCESS_WITH_CALLBACK);
		}
		else
		{
			KdPrint(("FileDisk: Create10M�ռ����\n"));
			Data->IoStatus.Status = STATUS_MEDIA_WRITE_PROTECTED;
			Data->IoStatus.Information = 0;
			return FLT_PREOP_COMPLETE;
		}
	}

	if (memcmp(PsGetProcessImageFileName(PsGetCurrentProcess()), "Format.exe", strlen("Format.exe")) == 0 ||
		memcmp(PsGetProcessImageFileName(PsGetCurrentProcess()), "DiskFormat.exe", strlen("DiskFormat.exe")) == 0 ||
		memcmp(PsGetProcessImageFileName(PsGetCurrentProcess()), "EstSipSrv.exe", strlen("EstSipSrv.exe")) == 0)
	{
		KdPrint(("FileDisk: ��ǰ�����Ľ���ΪFormat.exe���Ź��˽���\n"));
		return FLT_PREOP_SUCCESS_WITH_CALLBACK;
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


NTSTATUS
CreateFileDir(PWCHAR pwFileName, BOOLEAN bDirectory)
{
	HANDLE FileHandle = NULL;
	OBJECT_ATTRIBUTES ObjectAttributes;
	UNICODE_STRING uFileName;
	PWCHAR pwNameBuf = NULL;
	IO_STATUS_BLOCK IoStatus;
	NTSTATUS Status;

	pwNameBuf = (PWCHAR)ExAllocatePoolWithTag(NonPagedPool, 1024, FILE_DISK_POOL_TAG);/*ExAllocateFromPagedLookasideList(&g_PagedFileName);*/

	if (pwNameBuf == NULL)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	__try{
		RtlZeroMemory(pwNameBuf, MAX_PATH_BYTES);

		RtlInitEmptyUnicodeString(&uFileName, pwNameBuf, MAX_PATH_BYTES);

		if (*(pwFileName + 1) == L':')
		{
			RtlAppendUnicodeToString(&uFileName, L"\\DosDevices\\");
		}
		RtlAppendUnicodeToString(&uFileName, pwFileName);

		InitializeObjectAttributes(&ObjectAttributes,			 // ptr to structure
			&uFileName,			// ptr to file spec
			OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,		// attributes
			NULL,						  // root directory handle
			NULL);					  // ptr to security descriptor

		KdPrint(("CreateFileDir: Name=%ws,bDir=%x\n", pwFileName, bDirectory));

		if (bDirectory)
		{
			Status = ZwCreateFile(&FileHandle,	   // returned file handle
				SYNCHRONIZE | FILE_READ_ATTRIBUTES,   // desired access
				&ObjectAttributes,			   // ptr to object attributes
				&IoStatus,						   // ptr to I/O status block
				NULL,							// alloc size = none
				FILE_ATTRIBUTE_NORMAL,
				FILE_SHARE_READ | FILE_SHARE_WRITE,
				FILE_OPEN_IF,
				FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
				NULL,	// eabuffer
				0);	// ealength
		}
		else
		{
			Status = ZwCreateFile(&FileHandle,	 // returned file handle
				SYNCHRONIZE | FILE_READ_ATTRIBUTES, // desired access
				&ObjectAttributes,			     // ptr to object attributes
				&IoStatus,						// ptr to I/O status block
				NULL,							// alloc size = none
				FILE_ATTRIBUTE_NORMAL,
				FILE_SHARE_READ | FILE_SHARE_WRITE,
				FILE_OPEN_IF,
				FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
				NULL,	// eabuffer
				0);	// ealength
		}
		if ((!NT_SUCCESS(Status)) || (!NT_SUCCESS(IoStatus.Status)))
		{
			KdPrint(("CreateFileDir: Error in create File/Dir %ws,Status=%x\n", pwFileName, Status));
		}
	}
	__finally
	{
		ExFreePoolWithTag(pwNameBuf, FILE_DISK_POOL_TAG);
		/*ExFreeToPagedLookasideList(&g_PagedFileName, pwNameBuf);*/
	}
	if (FileHandle != NULL)
	{
		ZwClose(FileHandle);
	}
	return Status;
}



NTSTATUS CreateDirectory(IN PWCHAR pwFileName)
{

	NTSTATUS Status;

	PWCHAR pwDir = NULL;

	PWCHAR pwDirEnd = pwFileName;

	ULONG nNameLen = wcslen(pwFileName);

	PWCHAR pwEnd = pwFileName + nNameLen;

	ULONG nNum = 0;

	if ((nNameLen >= 512) || (nNameLen < 3)) return STATUS_BAD_DESCRIPTOR_FORMAT;

	pwDir = (PWCHAR)ExAllocatePoolWithTag(NonPagedPool, 1024, FILE_DISK_POOL_TAG);/*ExAllocateFromPagedLookasideList(&g_PagedFileName);*/

	if (pwDir == NULL)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	//Find the correct begin position
	//such as \??\C:\XXXXX\YYYYY,\??\SSCFS\
			
	__try{

		pwDirEnd++; //skip the first backslash

		while (pwDirEnd < pwEnd)
		{
			if (*pwDirEnd == L':') nNum = 0;
			if (*pwDirEnd == L'\\') nNum++;
			if (2 == nNum)  { break; }
			pwDirEnd++;
		}

		if (pwDirEnd == pwEnd)
		{
			pwDir = pwFileName;
		}
		//Create every sub Directory one bye one
		while (pwDirEnd < pwEnd)
		{
			if (*pwDirEnd == L'\\')
			{
				RtlZeroMemory(pwDir, MAX_PATH_BYTES);

				wcsncpy(pwDir, pwFileName, pwDirEnd - pwFileName);

				Status = CreateFileDir(pwDir, TRUE);
			}
			pwDirEnd++;
		}
	}
	__finally{

		ExFreePoolWithTag(pwDir, FILE_DISK_POOL_TAG);
		/*ExFreeToPagedLookasideList(&g_PagedFileName, pwDir);*/
	}
	return STATUS_SUCCESS;
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
	//UNREFERENCED_PARAMETER(Data);
	//UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(Flags);
	PFLT_FILE_NAME_INFORMATION nameInfo;
	NTSTATUS status;
	PWCHAR fullpath_name;
	UNICODE_STRING uDiskName = { 0 };
	UNICODE_STRING us_fullpath_name;
	BOOLEAN scanFile;
	PSCANNER_STREAM_HANDLE_CONTEXT scannerContext;
	UNICODE_STRING	unDestFileName = { 0 };
	OBJECT_ATTRIBUTES objAttributes = { 0 };
	HANDLE FileHandle = NULL;
	PFLT_INSTANCE FltBackInstance = NULL;
	PFILE_OBJECT FileObj = NULL;
	IO_STATUS_BLOCK Block = { 0 };


	if (g_backFilePath)   //����ͻ����и����ļ�����·����˵�������ļ����
	{

		//���ﴦ���ļ����
		//
		//  If this create was failing anyway, don't bother scanning now.
		//

		if (!NT_SUCCESS(Data->IoStatus.Status) ||
			(STATUS_REPARSE == Data->IoStatus.Status)) {

			return FLT_POSTOP_FINISHED_PROCESSING;
		}

		//
		//  Check if we are interested in this file.
		//

		status = FltGetFileNameInformation(Data,
			FLT_FILE_NAME_NORMALIZED |
			FLT_FILE_NAME_QUERY_DEFAULT,
			&nameInfo);

		if (!NT_SUCCESS(status)) {

			return FLT_POSTOP_FINISHED_PROCESSING;
		}

		FltParseFileNameInformation(nameInfo);

		if (FlagOn(Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess,
			FILE_WRITE_DATA | FILE_APPEND_DATA |
			DELETE | FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA |
			WRITE_DAC | WRITE_OWNER | ACCESS_SYSTEM_SECURITY))						//����ļ��䶯
		{
			//
			//  Check if the extension matches the list of extensions we are interested in
			//

			scanFile = ScannerpCheckExtension(&nameInfo->Extension);   //�����ж��Ƿ�Ϊ����Ȥ���ļ���������չ��


			if (scanFile)
			{
				RtlInitUnicodeString(&uDiskName, /*L"\\??\\C:\\backfile"*/g_backFilePath);   //Ӧ�ò�ֱ�Ӵ����������ַ���
				fullpath_name = GetFileAppFullPath(&uDiskName, 0, nameInfo);

				RtlInitUnicodeString(&us_fullpath_name, fullpath_name);

				KdPrint(("�������ļ�Ϊ��%wZ\n", &us_fullpath_name));

				RtlInitUnicodeString(&unDestFileName, fullpath_name);     //Ŀ���ļ���
				InitializeObjectAttributes(&objAttributes, &unDestFileName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
				status = FltCreateFile(g_FilterHandle,
					NULL,
					&FileHandle,
					SYNCHRONIZE | GENERIC_WRITE | GENERIC_READ,
					&objAttributes,
					&Block,
					NULL,
					FILE_ATTRIBUTE_NORMAL,
					FILE_SHARE_READ | FILE_SHARE_WRITE,
					FILE_OVERWRITE_IF,
					FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
					NULL,
					0,
					IO_FORCE_ACCESS_CHECK);

				if (STATUS_OBJECT_PATH_NOT_FOUND == status)
				{
					//Ŀ¼�����ɹ����ٴ����ļ�
					status = CreateDirectory(fullpath_name);
					if (!NT_SUCCESS(status))
					{
						KdPrint(("IsoVfsPostCreateBackFile error:%08x-%wZ\n", status, &unDestFileName));
					}
					KdPrint(("FileDisk: MiniFilter Ŀ¼����ʧ��\n"));
					status = FltCreateFile(g_FilterHandle,
						NULL,
						&FileHandle,
						SYNCHRONIZE | GENERIC_WRITE | GENERIC_READ,
						&objAttributes,
						&Block,
						NULL,
						FILE_ATTRIBUTE_NORMAL,
						FILE_SHARE_READ | FILE_SHARE_WRITE,
						FILE_OVERWRITE_IF,
						FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
						NULL,
						0,
						IO_FORCE_ACCESS_CHECK);
				}

				if (STATUS_OBJECT_NAME_NOT_FOUND == status)
				{
					status = FltCreateFile(g_FilterHandle,
						NULL,
						&FileHandle,
						SYNCHRONIZE | GENERIC_WRITE | GENERIC_READ,
						&objAttributes,
						&Block,
						NULL,
						FILE_ATTRIBUTE_NORMAL,
						FILE_SHARE_READ | FILE_SHARE_WRITE,
						FILE_OVERWRITE_IF,
						FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
						NULL,
						0,
						IO_FORCE_ACCESS_CHECK);
				}

				//����ļ�����û�д����ɹ����򷵻�
				if (!NT_SUCCESS(status))
				{
					KdPrint(("FileDisk: �ļ�û�д����ɹ���������֮����\n"));
					return FLT_POSTOP_FINISHED_PROCESSING;
				}

				status = ObReferenceObjectByHandle(FileHandle, 0, NULL, KernelMode, (PVOID*)&FileObj, NULL);

				if (!FltBackInstance)
				{
					status = GetOurInstanceFromVolume(g_FilterHandle, FileObj, &FltBackInstance);
					if (!NT_SUCCESS(status))
					{
						KdPrint(("CopyFileToBackupDir GetFilterInstance error:%08x\n", status));
					}
				}

				//
				//
				//  The create has requested write access, mark to rescan the file.
				//  Allocate the context.
				//

				status = FltAllocateContext(FltObjects->Filter,
					FLT_STREAMHANDLE_CONTEXT,
					sizeof(SCANNER_STREAM_HANDLE_CONTEXT),
					PagedPool,
					&scannerContext);

				if (NT_SUCCESS(status)) {

					//
					//  Set the handle context.
					//

					scannerContext->RescanRequired = TRUE;
					scannerContext->FileHandle = FileHandle;
					scannerContext->FileObj = FileObj;
					scannerContext->FltBackInstance = FltBackInstance;

					(VOID)FltSetStreamHandleContext(Data->Iopb->TargetInstance,
						Data->Iopb->TargetFileObject,
						FLT_SET_CONTEXT_REPLACE_IF_EXISTS,
						scannerContext,
						NULL);

					//
					//  Normally we would check the results of FltSetStreamHandleContext
					//  for a variety of error cases. However, The only error status 
					//  that could be returned, in this case, would tell us that
					//  contexts are not supported.  Even if we got this error,
					//  we just want to release the context now and that will free
					//  this memory if it was not successfully set.
					//

					//
					//  Release our reference on the context (the set adds a reference)
					//

					FltReleaseContext(scannerContext);
				}
			}
		}

	}

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

	if (g_formatting || (ULONG)PsGetCurrentProcessId() < 5) //0--4���̷Ź�
	{
		KdPrint(("FileDisk: ע���зŹ�����\n"));
		return (FLT_PREOP_SUCCESS_WITH_CALLBACK);
	}

	if (memcmp(PsGetProcessImageFileName(PsGetCurrentProcess()), "Format.exe", strlen("Format.exe")) == 0 ||
		memcmp(PsGetProcessImageFileName(PsGetCurrentProcess()), "DiskFormat.exe", strlen("DiskFormat.exe")) == 0 ||
		memcmp(PsGetProcessImageFileName(PsGetCurrentProcess()), "EstSipSrv.exe", strlen("EstSipSrv.exe")) == 0)
	{
		KdPrint(("FileDisk: ��ǰ�����Ľ���ΪFormat.exe���Ź��˽���\n"));
		return FLT_PREOP_SUCCESS_WITH_CALLBACK;
	}

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

	PSCANNER_STREAM_HANDLE_CONTEXT context = NULL;
	NTSTATUS status;
	PUCHAR buffer;
	FLT_PREOP_CALLBACK_STATUS returnStatus = FLT_PREOP_SUCCESS_NO_CALLBACK;
	PVOID back_buffer = NULL;

	PBACKE_FILE_RECORD back_file_record = NULL;
	KLOCK_QUEUE_HANDLE connListLockHandle;


	if (g_formatting || (ULONG)PsGetCurrentProcessId() < 5) //0--4���̷Ź�
	{
		KdPrint(("FileDisk: ע���зŹ�����\n"));
		return (FLT_PREOP_SUCCESS_WITH_CALLBACK);
	}

	if (memcmp(PsGetProcessImageFileName(PsGetCurrentProcess()), "Format.exe", strlen("Format.exe")) == 0 ||
		memcmp(PsGetProcessImageFileName(PsGetCurrentProcess()), "DiskFormat.exe", strlen("DiskFormat.exe")) == 0 ||
		memcmp(PsGetProcessImageFileName(PsGetCurrentProcess()), "EstSipSrv.exe", strlen("EstSipSrv.exe")) == 0)
	{
		KdPrint(("FileDisk: ��ǰ�����Ľ���ΪFormat.exe���Ź��˽���\n"));
		return FLT_PREOP_SUCCESS_WITH_CALLBACK;
	}

	//ӵ�ж�дȨ��
	if (FlagOn(g_filediskAuthority, FILEDISK_WRITE_AUTHORITY))
	{
		KdPrint(("FileDisk MiniFilter: IRP_MJ_READ Authority: FILEDISK_WRITE_AUTHORITY\n"));

		if (g_backFilePath)
		{
			status = FltGetStreamHandleContext(FltObjects->Instance,
				FltObjects->FileObject,
				&context);
			if (!NT_SUCCESS(status))
			{

				return (FLT_PREOP_SUCCESS_WITH_CALLBACK);
			}


			if (context->FileObj)
			{

				if (Data->Iopb->Parameters.Write.Length != 0)
				{
					back_file_record = (PBACKE_FILE_RECORD)ExAllocatePoolWithTag(NonPagedPool, sizeof(BACKE_FILE_RECORD), FILE_DISK_POOL_TAG);

					back_buffer = ExAllocatePoolWithTag(NonPagedPool, Data->Iopb->Parameters.Write.Length, FILE_DISK_POOL_TAG);
					if (!back_buffer)
					{
						KdPrint(("IsoVfsPreRedirectWithCallback:%p Alloc buffer error\n", FltObjects->FileObject));
						Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
						Data->IoStatus.Information = 0;
						return FLT_PREOP_COMPLETE;

					}


					if (Data->Iopb->Parameters.Write.MdlAddress != NULL)
					{

						buffer = MmGetSystemAddressForMdlSafe(Data->Iopb->Parameters.Write.MdlAddress,
							NormalPagePriority | MdlMappingNoExecute);


						if (buffer == NULL)
						{
							Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
							Data->IoStatus.Information = 0;
							returnStatus = FLT_PREOP_COMPLETE;

						}

						back_file_record->MdlLeng = MmGetMdlByteCount(Data->Iopb->Parameters.Write.MdlAddress);

					}
					else
					{
						buffer = Data->Iopb->Parameters.Write.WriteBuffer;
					}

					RtlCopyMemory(back_buffer, buffer, Data->Iopb->Parameters.Write.Length);
					back_file_record->Length = Data->Iopb->Parameters.Write.Length;;
					back_file_record->offset.QuadPart = Data->Iopb->Parameters.Write.ByteOffset.QuadPart;
					back_file_record->buffer = back_buffer;
					back_file_record->FileHandle = context->FileHandle;
					back_file_record->FileObject = context->FileObj;
					back_file_record->FltInstance = context->FltBackInstance;
					//�Ƿ���Ҫ�ر��ļ����
					back_file_record->isCloseHanle = FALSE;

				}

				KeAcquireInStackQueuedSpinLock(
					&gConnListLock,
					&connListLockHandle
					);
				InsertTailList(&gConnList, &back_file_record->listEntry);
				KeReleaseInStackQueuedSpinLock(&connListLockHandle);

				KeSetEvent(&gWorkerEvent, IO_NO_INCREMENT, FALSE);
			}

		}


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
	if (g_filediskAuthority == FILEDISK_NONE_AUTHORITY)
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

#define MAX_PATH 256

//����\\??\\c:-->\\device\\\harddiskvolume1
//LinkTarget.Bufferע��Ҫ�ͷ�

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
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
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

//����\\Device\\harddiskvolume1
//���C:
//DosName.Buffer���ڴ�ǵ��ͷ�

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

		//DosName->Buffer �������Ҫ�����ڴ�
		return STATUS_SUCCESS;
	}

	return status;
}



// ���� \\Device\\harddiskvolume1
// ��� 0 or 1 or 2
// ͨ���豸����ȡ������̺�

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

	WCHAR wc_symbolicLink[512] = { 0 };
	UNICODE_STRING symbolicLink;
	UNICODE_STRING linkTarget = { 0 };

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

			// 			KdPrint(("FileDisk: �����ķ������ӣ�%wZ\n", &symbolicLink));

			status = QuerySymbolicLink(&symbolicLink, &linkTarget);
			if (!NT_SUCCESS(status))
			{
				continue;
			}

			if (RtlEqualUnicodeString(&linkTarget, DeviceName, TRUE))
			{
				isFind = TRUE;
				ExFreePool(linkTarget.Buffer);
				KdPrint(("FileDisk: �ô��̵������Ϊ��%d\n", harddiskNo));
				break;
			}
			ExFreePool(linkTarget.Buffer);
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


BOOLEAN
	Is10MVolume(
	IN ULONG hardDiskNo
	)
{
	UNICODE_STRING                          DeviceName = { 0 };
	WCHAR                                           wc_DeviceName[512] = { 0 };
	OBJECT_ATTRIBUTES                       uDiskOa;
	HANDLE                                          hUDisk;
	IO_STATUS_BLOCK                         iostatus;
	PUCHAR                                          buffer = NULL;
	LARGE_INTEGER                           fileOffset;
	NTSTATUS                                        status;
	LARGE_INTEGER                           partitionSize = { 0 };
	ULONG                                           partitionSectors;

	RtlInitEmptyUnicodeString(&DeviceName, wc_DeviceName, 512 * sizeof(WCHAR));
	RtlStringCbPrintfW(DeviceName.Buffer, 512 * sizeof(WCHAR), L"\\??\\physicaldrive%d", hardDiskNo);
	DeviceName.Length = wcslen(DeviceName.Buffer) * 2;

	if (hardDiskNo != 0)
	{

		InitializeObjectAttributes(&uDiskOa,
			&DeviceName,
			OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
			NULL,
			NULL);

		status = ZwCreateFile(&hUDisk,
			GENERIC_READ | GENERIC_WRITE,
			&uDiskOa,
			&iostatus,
			NULL,
			FILE_ATTRIBUTE_NORMAL,
			FILE_SHARE_READ | FILE_SHARE_WRITE,
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
		KdPrint(("FileDisk: is10M CreateFile success\n"));

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

		KdPrint(("FileDisk: is10M readfile success\n"));

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
	UNICODE_STRING				DosName = { 0 };			//ͨ���豸���ƻ�ȡ���̷�

	ULONG						harddiskNo = 0;			//������̺�
	PVOLUME_CONTEXT                         ctx = NULL;


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


		//��ȡ�̷�
		status = MyRtlVolumeDeviceToDosName(workingName, &DosName);

		MyRtlVolumeDeviceGetPhysicalNumber(workingName, &harddiskNo);

		if (NT_SUCCESS(status) && DosName.Buffer != NULL)   //��ʱDosName��Ϊ�գ�����һ��
		{
			KdPrint(("FileDisk: MINI_FILTER realDeviceName: %wZ\n", workingName));

			context = (PREAD_UDISK_CONTEXT)ExAllocatePoolWithTag(NonPagedPool, sizeof(READ_UDISK_CONTEXT), FILE_DISK_POOL_TAG);

			context->deviceName = (PWCH)ExAllocatePoolWithTag(NonPagedPool, 2 * wcslen(DosName.Buffer) + 2, FILE_DISK_POOL_TAG);  //�������ֽ��������0000
			RtlZeroMemory(context->deviceName, 2 * wcslen(DosName.Buffer) + 2);

			RtlCopyMemory(context->deviceName, DosName.Buffer, 2 * wcslen(DosName.Buffer));
			context->hardDiskNo = harddiskNo;

			ExFreePoolWithTag(DosName.Buffer, FILE_DISK_POOL_TAG);


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



			//�ж�������Ƿ���10M�Ŀռ�
			if (Is10MVolume(harddiskNo))
			{
				RtlZeroMemory(devicePath, 260);
				if (FDUnicodeStringToChar(workingName, devicePath))
				{
					//
					if (strstr(devicePath, "\\DEVICE\\HARDDISKVOLUME") != NULL)
					{
						status = FltAllocateContext(
							FltObjects->Filter,
							FLT_VOLUME_CONTEXT,
							sizeof(VOLUME_CONTEXT),
							NonPagedPool,
							&ctx
							);

						if (NT_SUCCESS(status))
						{
							RtlZeroMemory(ctx, sizeof(VOLUME_CONTEXT));
							FltSetVolumeContext(
								FltObjects->Volume,
								FLT_SET_CONTEXT_REPLACE_IF_EXISTS,
								ctx,
								NULL);

							KdPrint(("FileDisk: ����������\n"));
							KdPrint(("FileDisk: ��10M�ľ���Ϊ��%wZ\n", workingName));
						}

						KdPrint(("FileDisk: ����10M�ռ�\n"));
						return STATUS_SUCCESS;
					}
				}
			}
			//return STATUS_SUCCESS;

		}
		//else
		//{
		//	return STATUS_FLT_DO_NOT_ATTACH;
		//}

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

			//  			KdPrint(("FileDisk: MINI_FILTER realDeviceName: %wZ\n", workingName));
			RtlZeroMemory(devicePath, 260);
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
	ULONGLONG					diskSize = 0;			//���̴�С

	PFILEDISK_VERIFY			fileDiskVerify;
	ULONG						verifyCode;

	NTSTATUS					status;

	PFILEDISK_NOTIFICATION		notification;		//����֪ͨӦ�ò����Ϣ
	ULONG						replyLength = 0;

	UNICODE_STRING				DeviceName = { 0 };
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
		// \??\physicaldrive0 ��ϵͳ���ڵ��̣����Ϊ0�Ļ�������̲���ָ����u��

		InitializeObjectAttributes(&uDiskOa,
			&DeviceName,
			OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
			NULL,
			NULL);

		status = ZwCreateFile(&hUDisk,
			GENERIC_READ | GENERIC_WRITE,
			&uDiskOa,
			&iostatus,
			NULL,
			FILE_ATTRIBUTE_NORMAL,
			FILE_SHARE_READ | FILE_SHARE_WRITE,
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

		//У��ṹ��������Ƿ�ı��  crc

		fileDiskVerify = (PFILEDISK_VERIFY)buffer;
		diskSize = *(ULONGLONG *)&fileDiskVerify->diskSize;
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

	}
	else
	{
		notification->isSpecial = 0;
	}



	notification->fileDiskAuthority = 0;
	notification->offset.QuadPart = 0;
	notification->phyNo = hardDiskNo;
	notification->storageSize.QuadPart = diskSize;
	KdPrint(("FileDisk: ���̵Ĵ�СΪ��%lld\n", diskSize));
	RtlCopyMemory(notification->Contents, ((PREAD_UDISK_CONTEXT)Context)->deviceName, wcslen(((PREAD_UDISK_CONTEXT)Context)->deviceName));

	ExFreePoolWithTag(((PREAD_UDISK_CONTEXT)Context)->deviceName, FILE_DISK_POOL_TAG);
	ExFreePoolWithTag(Context, FILE_DISK_POOL_TAG);

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


PWCHAR
	GetFileAppFullPath(PUNICODE_STRING dosname, USHORT DirLen, PFLT_FILE_NAME_INFORMATION filename)
{
	USHORT name_len = 0;
	PWCHAR filedos_path = NULL;
	NTSTATUS status = STATUS_SUCCESS;
	UNICODE_STRING unicode_path = { 0 };

	if ((0 == dosname->Length) || (NULL == filename))
	{
		goto CLEANUP;
	}
	//
	//Ӧ�ò�������Ƿ� dos���� +  + share�������� + ��Ŀ¼���� + �ļ����֣�flt��Ҫ��ȥ�������֣�
	//
	name_len = DirLen + dosname->Length + filename->Share.Length + filename->ParentDir.Length + filename->FinalComponent.Length + sizeof(WCHAR) * 2;
	if (name_len > MAX_PATH_BYTES)
	{
		DbgPrint("GetFileAppFullPath PathTool long\n");
		return NULL;
	}
	filedos_path = (PWCHAR)ExAllocatePoolWithTag(PagedPool, name_len, FILE_DISK_POOL_TAG);
	if (NULL == filedos_path)
	{
		goto CLEANUP;
	}
	RtlZeroBytes(filedos_path, name_len);
	unicode_path.Buffer = filedos_path;
	unicode_path.Length = 0;
	unicode_path.MaximumLength = name_len;
	RtlCopyUnicodeString(&unicode_path, dosname);

	if (filename->Share.Length)
	{
		status = RtlAppendUnicodeStringToString(&unicode_path, &filename->Share);
	}
	status = RtlAppendUnicodeStringToString(&unicode_path, &filename->ParentDir);
	if (!NT_SUCCESS(status))
	{

	}
	status = RtlAppendUnicodeStringToString(&unicode_path, &filename->FinalComponent);
	if (!NT_SUCCESS(status))
	{
	}
	RtlZeroBytes(&filedos_path[(name_len - DirLen - sizeof(WCHAR) * 2 - filename->Stream.Length) / sizeof(WCHAR)],
		sizeof(WCHAR) + filename->Stream.Length);
CLEANUP:
	return filedos_path;
}


NTSTATUS
GetOurInstanceFromVolume(
__in PFLT_FILTER  Filter,
__in PFILE_OBJECT FileObject,
__out PFLT_INSTANCE *OutInstance
)
{
	NTSTATUS        Status;
	PFLT_INSTANCE   Instance = NULL;
	ULONG           NumberInstancesReturned;
	PFLT_VOLUME     Volume = NULL;

	*OutInstance = NULL;
	__try
	{
		Status = FltGetVolumeFromFileObject(g_FilterHandle, FileObject, &Volume);
		if (!NT_SUCCESS(Status)) { __leave; }

		Status = FltEnumerateInstances(Volume, Filter, &Instance, 1, &NumberInstancesReturned);
		if (NT_SUCCESS(Status)) { *OutInstance = Instance; }


	}
	__finally
	{
		if (Volume) { FltObjectDereference(Volume); }
		if (Instance) { FltObjectDereference(Instance); }
	}
	return Status;
}


//
//�����ŵĽڵ�
//
void
TLInspectWorker(
IN PVOID StartContext
)
{
	NTSTATUS status;

	PBACKE_FILE_RECORD packet = NULL;
	LIST_ENTRY* listEntry;
	KLOCK_QUEUE_HANDLE connListLockHandle;

	UNREFERENCED_PARAMETER(StartContext);

	for (;;)
	{

		if (IsListEmpty(&gConnList))
		{
			KeWaitForSingleObject(
				&gWorkerEvent,
				Executive,
				KernelMode,
				FALSE,
				NULL
				);
		}

		while (!IsListEmpty(&gConnList))
		{
			packet = NULL;
			listEntry = NULL;
			KeAcquireInStackQueuedSpinLock(
				&gConnListLock,
				&connListLockHandle
				);

			if (!IsListEmpty(&gConnList))
			{
				listEntry = gConnList.Flink;
				packet = CONTAINING_RECORD(
					listEntry,
					BACKE_FILE_RECORD,
					listEntry
					);
				RemoveEntryList(&packet->listEntry);
			}

			KeReleaseInStackQueuedSpinLock(&connListLockHandle);

			if (packet != NULL)
			{
				DoWriteFile(packet);
			}
		}
	}



	PsTerminateSystemThread(STATUS_SUCCESS);

}



void DoWriteFile(PBACKE_FILE_RECORD packet)
{
	PFILE_OBJECT fileObj = packet->FileObject;
	IO_STATUS_BLOCK ioStatus = { 0 };
	PBACKE_FILE_RECORD handleContext = NULL;

	KdPrint(("DoWriteFile Pre:%p\n", packet->FileObject));

	if (packet->FltInstance)
	{
		if (!packet->isCloseHanle)
		{
			ioStatus.Status = FltWriteFile(packet->FltInstance,
				packet->FileObject,
				&packet->offset,
				packet->Length,
				packet->buffer,
				0,
				NULL,
				NULL,
				NULL);
		}
		else
		{
			ioStatus.Status = FltClose(packet->FltInstance);
		}
	}
	else
	{
		if (!packet->isCloseHanle)
		{
			ioStatus.Status = ZwWriteFile(packet->FileHandle, NULL, NULL, NULL,
				&ioStatus,
				packet->buffer,
				packet->Length,
				&packet->offset,
				NULL);
		}
		else
		{
			ioStatus.Status = FltClose(packet->FileHandle);
		}

	}
	KdPrint(("DoWriteFile Post:%p, status:%08x, %p\n", packet->IsoFileObjects, ioStatus.Status, handleContext));
	if (STATUS_DISK_FULL == ioStatus.Status)
	{

	}



	if (packet->buffer)
	{
		ExFreePoolWithTag(packet->buffer, FILE_DISK_POOL_TAG);
		packet->buffer = NULL;
	}



}


BOOLEAN
ScannerpCheckExtension(
_In_ PUNICODE_STRING Extension
)
/*++

Routine Description:

Checks if this file name extension is something we are interested in

Arguments

Extension - Pointer to the file name extension

Return Value

TRUE - Yes we are interested
FALSE - No
--*/
{
	ULONG count;

	if (Extension->Length == 0) {

		return FALSE;
	}

	if (ScannedExtensions == NULL)
	{
		//˵��û�п����ļ����
		return FALSE;
	}

	//
	//  Check if it matches any one of our static extension list
	//

	for (count = 0; count < ScannedExtensionCount; count++) {

		if (RtlCompareUnicodeString(Extension, ScannedExtensions + count, TRUE) == 0) {

			//
			//  A match. We are interested in this file
			//

			return TRUE;
		}
	}

	return FALSE;
}


FLT_PREOP_CALLBACK_STATUS MiniFilterPreCleanUpCallback(
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

FLT_POSTOP_CALLBACK_STATUS MiniFilterPostCleanUpCallback(
	PFLT_CALLBACK_DATA Data,
	PCFLT_RELATED_OBJECTS FltObjects,
	PVOID CompletionContext,
	FLT_POST_OPERATION_FLAGS Flags
	)
{
// 	UNREFERENCED_PARAMETER(Data);
// 	UNREFERENCED_PARAMETER(FltObjects);
// 	UNREFERENCED_PARAMETER(CompletionContext);
// 	UNREFERENCED_PARAMETER(Flags);

	NTSTATUS status;
	PSCANNER_STREAM_HANDLE_CONTEXT scannerContext;
	PFSRTL_COMMON_FCB_HEADER srvFileFcb = NULL;
	IO_STATUS_BLOCK ioBlock = { 0 };
	PBACKE_FILE_RECORD back_file_record = NULL;
	KLOCK_QUEUE_HANDLE connListLockHandle;


	status = FltGetStreamHandleContext(FltObjects->Instance,
		FltObjects->FileObject,
		(PFLT_CONTEXT*)&scannerContext);

	if (!NT_SUCCESS(status))
	{
		return (FLT_POSTOP_FINISHED_PROCESSING);
	}

	if (scannerContext)
	{
		//�ļ���С�����õĻ��ᵼ��pdf���ļ����ݴ�С����ͬ
		srvFileFcb = (PFSRTL_COMMON_FCB_HEADER)FltObjects->FileObject->FsContext;
		ZwSetInformationFile(scannerContext->FileHandle, &ioBlock, &srvFileFcb->FileSize, sizeof(LARGE_INTEGER), FileEndOfFileInformation);

// 		if (scannerContext->FileHandle)
// 		{
// 			FltClose(scannerContext->FileHandle);
// 			scannerContext->FileHandle = NULL;
// 		}
		back_file_record = (PBACKE_FILE_RECORD)ExAllocatePoolWithTag(NonPagedPool, sizeof(BACKE_FILE_RECORD), FILE_DISK_POOL_TAG);
		RtlZeroMemory(back_file_record, sizeof(BACKE_FILE_RECORD));

		back_file_record->isCloseHanle = TRUE;
		back_file_record->FileHandle = scannerContext->FileHandle;

		KeAcquireInStackQueuedSpinLock(
			&gConnListLock,
			&connListLockHandle
			);
		InsertTailList(&gConnList, &back_file_record->listEntry);
		KeReleaseInStackQueuedSpinLock(&connListLockHandle);

		KeSetEvent(&gWorkerEvent, IO_NO_INCREMENT, FALSE);

		FltReleaseContext(scannerContext);

	}

	return (FLT_POSTOP_FINISHED_PROCESSING);
}