// FileDiskDynamic.cpp : 定义 DLL 应用程序的导出函数。
//
#include "stdafx.h"
#include <stdlib.h>
#include "FileDiskDynamic.h"
#include "DiskOption.h"

#include "crc32.h"

#include <ShlObj.h>
#include <winioctl.h>
#include <stdio.h>

HANDLE g_hPort, g_completion = INVALID_HANDLE_VALUE;
//U盘偏移	10M+2048保留扇区+1024字节
#define UDISKOFFSET			(10485760 + 1024 + 1048576)

typedef struct _FILEDISK_NOTIFICATION
{
	BYTE			isSpecial;					//是否是特定的U盘
	ULONG			fileDiskAuthority;			//权限
	LARGE_INTEGER	offset;						//U盘偏移
	LARGE_INTEGER	storageSize;				//U盘大小
	UCHAR			Contents[512];				//保留字段
}FILEDISK_NOTIFICATION, *PFILEDISK_NOTIFICATION;

typedef struct _FILEDISK_REPLY {

	ULONG			fileDiskAuthority;			//应用层返回的权限

} FILEDISK_REPLY, *PFILEDISK_REPLY;


#pragma pack(1)

typedef struct _FILEDISK_MESSAGE {

	//
	//  Required structure header.
	//

	FILTER_MESSAGE_HEADER MessageHeader;


	//
	//  Private scanner-specific fields begin here.
	//

	FILEDISK_NOTIFICATION Notification;

	//
	//  Overlapped structure: this is not really part of the message
	//  However we embed it instead of using a separately allocated overlap structure
	//

	OVERLAPPED Ovlp;

} FILEDISK_MESSAGE, *PFILEDISK_MESSAGE;

typedef struct _FILEDISK_REPLY_MESSAGE {

	//
	//  Required structure header.
	//

	FILTER_REPLY_HEADER ReplyHeader;

	//
	//  Private scanner-specific fields begin here.
	//

	FILEDISK_REPLY Reply;

} FILEDISK_REPLY_MESSAGE, *PFILEDISK_REPLY_MESSAGE;


/************************************************************************/
/* 定义一些内存中的结构体                                                 */

typedef long	NTSTATUS;
typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
#ifdef MIDL_PASS
	[size_is(MaximumLength / 2), length_is((Length) / 2)] USHORT * Buffer;
#else // MIDL_PASS
	PWSTR  Buffer;
#endif // MIDL_PASS
} UNICODE_STRING;
typedef UNICODE_STRING *PUNICODE_STRING;
typedef const UNICODE_STRING *PCUNICODE_STRING;
#define UNICODE_NULL ((WCHAR)0) // winnt

typedef struct _OBJECT_ATTRIBUTES {
	ULONG Length;
	HANDLE RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;        // Points to type SECURITY_DESCRIPTOR
	PVOID SecurityQualityOfService;  // Points to type SECURITY_QUALITY_OF_SERVICE
} OBJECT_ATTRIBUTES;
typedef OBJECT_ATTRIBUTES *POBJECT_ATTRIBUTES;
typedef CONST OBJECT_ATTRIBUTES *PCOBJECT_ATTRIBUTES;

typedef struct _IO_STATUS_BLOCK {
	union {
		NTSTATUS Status;
		PVOID Pointer;
	};

	ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

EXTERN_C
{
	NTSYSAPI
	NTSTATUS
	WINAPI
	NtCreateFile(
	OUT PHANDLE FileHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN PLARGE_INTEGER AllocationSize OPTIONAL,
	IN ULONG FileAttributes,
	IN ULONG ShareAccess,
	IN ULONG CreateDisposition,
	IN ULONG CreateOptions,
	IN PVOID EaBuffer OPTIONAL,
	IN ULONG EaLength
	);

	NTSYSAPI
		ULONG
		WINAPI
		RtlNtStatusToDosError(
		NTSTATUS Status
		);

	NTSYSAPI
		NTSTATUS
		WINAPI
		NtClose(
		HANDLE Handle
		);

};


#define RtlInitUnicodeString(_u,_w)     {                                       \
    (_u)->Buffer=(_w);                                                          \
    (_u)->Length=static_cast<USHORT>( lstrlenW(_w)*sizeof( UNICODE_NULL ) );    \
    (_u)->MaximumLength=(_u)->Length+sizeof( UNICODE_NULL );                    \
}

#define NT_SUCCESS(_RS)     (0<=(_RS))

/************************************************************************/


//判断设备是否可用
BOOL QueryDeviceStatus(DWORD DeviceNumber)
{
	HANDLE                  hEnDisk;
	WCHAR                   wsDeviceName[MAX_PATH];
	WCHAR					wsSymbolicLink[MAX_PATH];
	OBJECT_ATTRIBUTES       ObjectAttributes;
	UNICODE_STRING          usDeviceName;
	IO_STATUS_BLOCK         IoSB;
	NTSTATUS                Status;

	BOOLEAN fMountStatus;
	DWORD   dwBytesReturned;
	DWORD   dwSaveErrorCode;

	swprintf(wsSymbolicLink, L"\\\\.\\LaLaLa%u", DeviceNumber);
	swprintf(wsDeviceName, L"\\Device\\FileDisk\\FileDisk%u", DeviceNumber);

// 	RtlInitUnicodeString(&usDeviceName, wsDeviceName);

// 	ObjectAttributes.Attributes = 0x40; // BJ_CASE_INSENSITIVE;
// 	ObjectAttributes.Length = sizeof(ObjectAttributes);
// 	ObjectAttributes.ObjectName = &usDeviceName;
// 	ObjectAttributes.RootDirectory = NULL;
// 	ObjectAttributes.SecurityDescriptor = NULL;
// 	ObjectAttributes.SecurityQualityOfService = NULL;
// 
// 	Status = NtCreateFile(&hEnDisk,
// 		SYNCHRONIZE,
// 		&ObjectAttributes,
// 		&IoSB,
// 		NULL,
// 		FILE_ATTRIBUTE_NORMAL,
// 		FILE_SHARE_READ | FILE_SHARE_WRITE,
// 		0x1, //FILE_OPEN,
// 		0x8 | 0x20, // FILE_NO_INTERMEDIATE_BUFFERING| FILE_SYNCHRONOUS_IO_NONALERT,
// 		NULL,
// 		0);
// 
// 	if (!NT_SUCCESS(Status))
// 	{
// 		SetLastError(RtlNtStatusToDosError(Status));
// 		return FALSE;
// 	}

	if (!DefineDosDeviceW(
		DDD_RAW_TARGET_PATH,
		&wsSymbolicLink[4],
		wsDeviceName
		))
	{
		return FALSE;
	}

	hEnDisk = CreateFileW(
		wsSymbolicLink,
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		FILE_FLAG_NO_BUFFERING,
		NULL
		);

	if (hEnDisk == INVALID_HANDLE_VALUE)
	{
		DefineDosDeviceW(DDD_REMOVE_DEFINITION, &wsSymbolicLink[4], NULL);
		return FALSE;
	}

	if (!DeviceIoControl(hEnDisk,
		IOCTL_FILE_DISK_QUERY_DEVICE_STATUS,
		NULL,
		0,
		&fMountStatus,
		sizeof(fMountStatus),
		&dwBytesReturned,
		NULL))
	{
		dwSaveErrorCode = GetLastError();
// 		NtClose(hEnDisk);
		CloseHandle(hEnDisk);
		SetLastError(dwSaveErrorCode);

		return FALSE;
	}

// 	NtClose(hEnDisk);
	CloseHandle(hEnDisk);
	SetLastError(NOERROR);

// 	DefineDosDeviceW(DDD_REMOVE_DEFINITION, &wsSymbolicLink[4], NULL);

	return TRUE;
}

//获得一个可用的设备号
DWORD GetAvailableDeviceNumber()
{
	DWORD deviceCount = 4;		//默认4个
	for (int i = 0; i < deviceCount; i++)
	{
		if (QueryDeviceStatus(i))
		{
			return i;
		}
	}
	return -1;
}

/************************************************************************
 判断刚才插入的u盘是否为特定的u盘
 传入盘符
************************************************************************/
BOOL IsSpecialUDisk(char driveLetter)
{
	DWORD	phyDiskNo = 0;

	CHAR path[MAX_PATH] = { 0 };

	if (!GetPhysicalNum(driveLetter, &phyDiskNo))
	{
		return FALSE;
	}

	sprintf(path, "\\\\.\\PHYSICALDRIVE%d", phyDiskNo);

	HANDLE hDrive = CreateFileA(path,
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_WRITE | FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_FLAG_NO_BUFFERING,
		NULL);
	if (hDrive == INVALID_HANDLE_VALUE)
	{
		OutputDebugStringW(L"IsSpecialUDisk CreateFile error\n");
		return FALSE;
	}

	char buffer[512] = { 0 };
	DWORD readReturn = 0;

	ULONGLONG byteOffset = 0;

	byteOffset = (2048 + 10 * 1024 *1024 / 512) * 512;

	OVERLAPPED over = { 0 };
	ZeroMemory(&over, sizeof(OVERLAPPED));
	over.hEvent = NULL;
	over.Offset = 0;
	over.OffsetHigh = 0;

	over.Offset = (ULONG)((byteOffset)& 0xFFFFFFFF);
	over.OffsetHigh = (ULONG)((byteOffset) >> 32);

	BOOL ret = ReadFile(hDrive, buffer, 512, &readReturn, &over);
	if (!ret)
	{
		CloseHandle(hDrive);
		return FALSE;
	}

	PFILEDISK_VERIFY fileDiskVerify;
	fileDiskVerify = (PFILEDISK_VERIFY)buffer;

	DWORD	verifyCode = fileDiskVerify->verifyCode;

	verifyCode = crc32(fileDiskVerify->code, 508);

	if (verifyCode == fileDiskVerify->verifyCode)
	{
		CloseHandle(hDrive);
		return TRUE;
	}
	else
	{
		CloseHandle(hDrive);
		return FALSE;
	}

	CloseHandle(hDrive);
	return TRUE;
}

DWORD
WINAPI
MessageWorker(
IN LPVOID pParam
)
/*++

Routine Description

This is a worker thread that


Arguments

Context  - This thread context has a pointer to the port handle we use to send/receive messages,
and a completion port handle that was already associated with the comm. port by the caller

Return Value

HRESULT indicating the status of thread exit.

--*/
{
	PFILEDISK_NOTIFICATION notification;
	FILEDISK_REPLY_MESSAGE replyMessage = {0};
	PFILEDISK_MESSAGE message;
	LPOVERLAPPED pOvlp;
	BOOL result;
	DWORD outSize;
	HRESULT hr;
	ULONG_PTR key;

	DWORD bytesReturned = 0;

	char outbuffer[512] = {0};
	char driveLetter = 0;				//记录传递上来的盘符

	message = (PFILEDISK_MESSAGE)malloc(sizeof(FILEDISK_MESSAGE));
#pragma warning(push)
#pragma warning(disable:4127) // conditional expression is constant

	while (TRUE) {

#pragma warning(pop)

		hr = FilterGetMessage(g_hPort,
			&message->MessageHeader,
			FIELD_OFFSET(FILEDISK_MESSAGE, Ovlp),
			NULL);

		if (!SUCCEEDED(hr)) {

			OutputDebugStringA("FilterGetMessage Error\n");

		}

		notification = &message->Notification;

		driveLetter = notification->Contents[0];
		OutputDebugStringA((char *)&notification->Contents);


// 		BOOL isSpecial = IsSpecialUDisk(driveLetter);
		BOOL isSpecial = notification->isSpecial;

		//打印调试信息
		if (!isSpecial)
		{
			OutputDebugStringW(L"这不是一个制作的u盘\n");
		}
		
		replyMessage.ReplyHeader.Status = 0;
		replyMessage.ReplyHeader.MessageId = message->MessageHeader.MessageId;

		//将专用介质的权限给驱动
		replyMessage.Reply.fileDiskAuthority = 2/*这里*/;

		printf("Replying message, fileDiskAuthority: %d\n", replyMessage.Reply.fileDiskAuthority);

		if (isSpecial)
		{
			//如果是指定的u盘，则直接挂出来

			POPEN_FILE_INFORMATION  OpenFileInformation;
			char FileName[MAX_PATH] = { 0 };
			DWORD PhyDriveNo = 0;
			DRIVEINFO DriveInfo = {0};
			GetPhysicalNum(driveLetter, &PhyDriveNo);

			//获取磁盘相关信息
// 			GetPhysicalDriveInfo(PhyDriveNo, &DriveInfo);
			DriveInfo.DiskSize = notification->storageSize.QuadPart;

			sprintf(FileName, "\\??\\physicaldrive%d", PhyDriveNo);
			OpenFileInformation =
				(POPEN_FILE_INFORMATION)malloc(sizeof(OPEN_FILE_INFORMATION) + strlen(FileName) + 7);

			if (OpenFileInformation == NULL)
			{
				return -1;
			}

			memset(
				OpenFileInformation,
				0,
				sizeof(OPEN_FILE_INFORMATION) + strlen(FileName) + 7
				);

			if (FileName[0] == '\\')
			{
				if (FileName[1] == '\\')
					// \\server\share\path\filedisk.img
				{
					strcpy(OpenFileInformation->FileName, "\\??\\UNC");
					strcat(OpenFileInformation->FileName, FileName + 1);
				}
				else
					// \Device\Harddisk0\Partition1\path\filedisk.img
				{
					strcpy(OpenFileInformation->FileName, FileName);
				}
			}
			else
				// c:\path\filedisk.img
			{
				strcpy(OpenFileInformation->FileName, "\\??\\");
				strcat(OpenFileInformation->FileName, FileName);
			}

			OpenFileInformation->FileNameLength =
				(USHORT)strlen(OpenFileInformation->FileName);

			OpenFileInformation->DriveLetter = driveLetter+1;
			OpenFileInformation->PhysicalDrive = TRUE;
			OpenFileInformation->FileOffset.QuadPart = UDISKOFFSET;
			OpenFileInformation->ReadOnly = FALSE;
			//u盘的大小
			OpenFileInformation->FileSize.QuadPart = DriveInfo.DiskSize - UDISKOFFSET;

			char strBuffer[512] = { 0 };
			sprintf(strBuffer, "磁盘的大小为high:%08x,low:%08x\n", OpenFileInformation->FileSize.HighPart, OpenFileInformation->FileSize.LowPart);
			OutputDebugStringA(strBuffer);

			DWORD DeviceNumber = GetAvailableDeviceNumber();
			if (DeviceNumber < 0)
			{
				OutputDebugStringW(L"获取不到可用的设备号\n");
				return -1;
			}
			OutputDebugStringW(L"开始挂载u盘\n");
			FileDiskMount(DeviceNumber, OpenFileInformation, FALSE);		//挂载u盘
		}

		if (SUCCEEDED(hr)) 
		{

			printf("Replied message\n");
			OutputDebugStringA("Replied message\n");

			//由于上面的没有把权限传递进去，现在马上传一个权限进去
			FilterSendMessage(g_hPort,
				&replyMessage.Reply,
				sizeof(FILEDISK_REPLY),
				NULL,
				NULL,
				&bytesReturned);

		}
		else 
		{

			sprintf(outbuffer, "Scanner: Error replying message. Error = 0x%X\n", hr);
			OutputDebugStringA(outbuffer);
		}


	}

	free(message);

	return hr;
}


extern "C" __declspec(dllexport) int InitialCommunicationPort(void)
{
	ULONG threadId = 0;
	DWORD hResult = FilterConnectCommunicationPort(
		NPMINI_PORT_NAME,
		0,
		NULL,
		0,
		NULL,
		&g_hPort);

	if (hResult != S_OK) {
		return hResult;
	}

// 	g_completion = CreateIoCompletionPort(g_hPort,
// 		NULL,
// 		0,
// 		NULL);

	CreateThread(
		NULL,
		0,
		MessageWorker,
		NULL,
		0,
		&threadId);

	return 0;
}

extern "C" __declspec(dllexport) int FDSendMessage(PVOID InputBuffer)
{
	DWORD bytesReturned = 0;
	DWORD hResult = 0;
	PDWORD commandMessage = (PDWORD)InputBuffer;

	FILEDISK_REPLY filedisk_reply = {0};		//设置权限进去
	filedisk_reply.fileDiskAuthority = *commandMessage;

	hResult = FilterSendMessage(
		g_hPort,
		&filedisk_reply,
		sizeof(FILEDISK_REPLY),
		NULL,
		NULL,
		&bytesReturned);

	if (hResult != S_OK) {
		return hResult;
	}
	return 0;
}

//挂载磁盘
__declspec(dllexport)	
int FileDiskMount(int DeviceNumber, 
POPEN_FILE_INFORMATION OpenFileInformation, 
BOOLEAN CdImage)
{
	char    VolumeName[] = "\\\\.\\ :";
	char    DriveName[] = " :\\";
	char    DeviceName[255];
	HANDLE  Device;
	DWORD   BytesReturned;
	char	strBuffer[512];
	DWORD	ioInputSize = 0;

	VolumeName[4] = OpenFileInformation->DriveLetter;
	DriveName[0] = OpenFileInformation->DriveLetter;

	Device = CreateFileA(
		VolumeName,
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		FILE_FLAG_NO_BUFFERING,
		NULL
		);

	if (Device != INVALID_HANDLE_VALUE)
	{
		CloseHandle(Device);
		sprintf(strBuffer, "FileDiskMount CreateFile Error, errCode: %d\n", GetLastError());
		OutputDebugStringA(strBuffer);
		return -1;
	}

	if (CdImage)
	{
		sprintf(DeviceName, DEVICE_NAME_PREFIX "Cd" "%u", DeviceNumber);
	}
	else
	{
		sprintf(DeviceName, DEVICE_NAME_PREFIX "%u", DeviceNumber);
	}

	if (!DefineDosDeviceA(
		DDD_RAW_TARGET_PATH,
		&VolumeName[4],
		DeviceName
		))
	{
		sprintf(strBuffer, "FileDiskMount DefineDosDeviceA Error, errCode: %d\n", GetLastError());
		OutputDebugStringA(strBuffer);
		return -1;
	}

	Device = CreateFileA(
		VolumeName,
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		FILE_FLAG_NO_BUFFERING,
		NULL
		);

	if (Device == INVALID_HANDLE_VALUE)
	{
		DefineDosDeviceA(DDD_REMOVE_DEFINITION, &VolumeName[4], NULL);
		sprintf(strBuffer, "FileDiskMount CreateFileA1 Error, errCode: %d\n", GetLastError());
		OutputDebugStringA(strBuffer);
		return -1;
	}

	ioInputSize = sizeof(OPEN_FILE_INFORMATION) + OpenFileInformation->FileNameLength - 1;

	sprintf(strBuffer, "FileDisk ioInputSize:%d\n", ioInputSize);
	OutputDebugStringA(strBuffer);

	if (!DeviceIoControl(
		Device,
		IOCTL_FILE_DISK_OPEN_FILE,
		OpenFileInformation,
		ioInputSize,
		NULL,
		0,
		&BytesReturned,
		NULL
		))
	{
		DefineDosDeviceA(DDD_REMOVE_DEFINITION, &VolumeName[4], NULL);
		CloseHandle(Device);
		sprintf(strBuffer, "FileDiskMount DeviceIoControl IOCTL_FILE_DISK_OPEN_FILE Error, errCode: %d\n", GetLastError());
		OutputDebugStringA(strBuffer);
		return -1;
	}

	CloseHandle(Device);

	SHChangeNotify(SHCNE_DRIVEADD, SHCNF_PATH, DriveName, NULL);

	return 0;
}

//卸载磁盘
__declspec(dllexport)
int FileDiskUmount(char DriveLetter)
{
	char    VolumeName[] = "\\\\.\\ :";
	char    DriveName[] = " :\\";
	HANDLE  Device;
	DWORD   BytesReturned;

	VolumeName[4] = DriveLetter;
	DriveName[0] = DriveLetter;

	Device = CreateFileA(
		VolumeName,
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		FILE_FLAG_NO_BUFFERING,
		NULL
		);

	if (Device == INVALID_HANDLE_VALUE)
	{
		fprintf(stderr, "FilediskUmount CreateFile error, errcode: %d\n", GetLastError());
		return -1;
	}


	if (!DeviceIoControl(
		(HANDLE)Device,            // handle to a volume
		(DWORD)FSCTL_DISMOUNT_VOLUME,   // dwIoControlCode
		NULL,                        // lpInBuffer
		0,                           // nInBufferSize
		NULL,                        // lpOutBuffer
		0,                           // nOutBufferSize
		&BytesReturned,   // number of bytes returned
		NULL  // OVERLAPPED structure
		))
	{
		CloseHandle(Device);
		fprintf(stderr, "FilediskUmount DeviceIoControl FSCTL_DISMOUNT_VOLUME error, errcode: %d\n", GetLastError());
		return -1;
	}


	//     if (!DeviceIoControl(
	//         Device,
	//         FSCTL_LOCK_VOLUME,
	//         NULL,
	//         0,
	//         NULL,
	//         0,
	//         &BytesReturned,
	//         NULL
	//         ))
	//     {
	//         PrintLastError(&VolumeName[4]);
	//         CloseHandle(Device);
	// 		fprintf(stderr, "FilediskUmount DeviceIoControl FSCTL_LOCK_VOLUME error, errcode: %d\n", GetLastError());
	//         return -1;
	//     }

	if (!DeviceIoControl(
		Device,
		IOCTL_FILE_DISK_CLOSE_FILE,
		NULL,
		0,
		NULL,
		0,
		&BytesReturned,
		NULL
		))
	{
		CloseHandle(Device);
		fprintf(stderr, "FilediskUmount DeviceIoControl IOCTL_FILE_DISK_CLOSE_FILE error, errcode: %d\n", GetLastError());
		return -1;
	}

	//     if (!DeviceIoControl(
	//         Device,
	//         FSCTL_DISMOUNT_VOLUME,
	//         NULL,
	//         0,
	//         NULL,
	//         0,
	//         &BytesReturned,
	//         NULL
	//         ))
	//     {
	//         PrintLastError(&VolumeName[4]);
	//         CloseHandle(Device);
	// 		fprintf(stderr, "FilediskUmount DeviceIoControl FSCTL_DISMOUNT_VOLUME error, errcode: %d\n", GetLastError());
	// 		return -1;
	//     }

	//     if (!DeviceIoControl(
	//         Device,
	//         FSCTL_UNLOCK_VOLUME,
	//         NULL,
	//         0,
	//         NULL,
	//         0,
	//         &BytesReturned,
	//         NULL
	//         ))
	//     {
	//         PrintLastError(&VolumeName[4]);
	//         CloseHandle(Device);
	// 		fprintf(stderr, "FilediskUmount DeviceIoControl FSCTL_UNLOCK_VOLUME error, errcode: %d\n", GetLastError());
	// 		return -1;
	//     }

	CloseHandle(Device);

	if (!DefineDosDeviceA(
		DDD_REMOVE_DEFINITION,
		&VolumeName[4],
		NULL
		))
	{
		fprintf(stderr, "FilediskUmount DefineDosDevice error, errcode: %d\n", GetLastError());
		return -1;
	}

	SHChangeNotify(SHCNE_DRIVEREMOVED, SHCNF_PATH, DriveName, NULL);

	return 0;
}


// 制作u盘
__declspec(dllexport)	BOOL MakeDisk(char DriveLetter)
{
	DWORD phyNum = 0;
	BOOL ret = GetPhysicalNum(DriveLetter, &phyNum);
	if (!ret)
	{
		OutputDebugStringW(L"获取物理磁盘号失败！\n");
		return FALSE;
	}
	DRIVEINFO driveInfo = { 0 };
	GetPhysicalDriveInfo(phyNum, &driveInfo);

	CHAR letterList[MAX_PATH] = { 0 };
	DWORD count = 0;
	GetLetterFromPhysicalDrive(phyNum, letterList, &count);

	OutputDebugStringW(L"操作之前解除锁定\n");
	//操作之前先解除锁定，以免出问题
	for (int i = 0; i < count; i++)
	{
		UnlockVolume(letterList[i]);
	}


	OutputDebugStringW(L"锁定和卸载所有卷\n");
	//锁定和卸载所有卷
	for (int i = 0; i < count; i++)
	{
		LockVolum(letterList[i]);
		DisMountVolum(letterList[i]);
	}

	OutputDebugStringW(L"删除分区信息\n");
	DWORD r = DestroyDisk(phyNum);
	if (r != 0)
	{
		OutputDebugStringW(L"删除分区失败\n");
		return FALSE;
	}

	//这里制作特殊u盘的函数
	WriteSpecialUDisk(letterList[0], phyNum, &driveInfo);

	OutputDebugString(L"格式化磁盘\n");
	//格式化磁盘
	DiskFormat(letterList[count - 1]);


	//格式化之后解锁
	for (int i = 0; i < count; i++)
	{
		UnlockVolume(letterList[i]);
	}


	//重新加载所有盘
	GetLogicalDrives();

	return TRUE;
}