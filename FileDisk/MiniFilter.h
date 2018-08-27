#ifndef _MINI_FILTER_
#define _MINI_FILTER_

#include <fltKernel.h>
#include <ntddk.h>


#define MINI_FILTER

#define FILEDISK_WRITE_AUTHORITY	0x00000002			//写权限，包括读
#define	FILEDISK_READ_AUTHORITY		0x00000001			//读权限
#define FILEDISK_NONE_AUTHORITY		0x00000000			//无权限，禁用
#define MAX_PATH_BYTES				1024

typedef unsigned char BYTE;


typedef struct _VOLUME_CONTEXT {

	ULONG is10MVolume;
	ULONG isSecUDisk;

} VOLUME_CONTEXT, *PVOLUME_CONTEXT;

typedef struct _SCANNER_STREAM_HANDLE_CONTEXT {

	BOOLEAN RescanRequired;
	HANDLE  FileHandle;
	PFLT_INSTANCE FltBackInstance;
	PFILE_OBJECT FileObj;

} SCANNER_STREAM_HANDLE_CONTEXT, *PSCANNER_STREAM_HANDLE_CONTEXT;

typedef struct BACKE_FILE_RECORD_str
{
	LIST_ENTRY listEntry;
	HANDLE       FileHandle;
	ULONG MdlLeng;

	ULONG Length;
	PVOID buffer;
	LARGE_INTEGER offset;

	BOOLEAN		isCloseHanle;			//用来判断文件是否写完，然后关闭句柄

	PFLT_INSTANCE  FltInstance;
	PFILE_OBJECT   FileObject;
	PFLT_INSTANCE  IsoFltInstance;
	PFILE_OBJECT IsoFileObjects;

}BACKE_FILE_RECORD, *PBACKE_FILE_RECORD;

typedef struct _FILEDISK_VERIFY_					//磁盘开始的512字节用于校验是否被改动
{
	BYTE				code[500];
	BYTE				diskSize[8];
	ULONG32				verifyCode;
}FILEDISK_VERIFY, *PFILEDISK_VERIFY;

typedef struct _FILEDISK_NOTIFICATION
{
	BYTE			isSpecial;					//是否是特定的U盘
	ULONG			fileDiskAuthority;			//权限
	ULONG			phyNo;						//物理磁盘号
	LARGE_INTEGER	offset;						//U盘偏移
	LARGE_INTEGER	storageSize;				//U盘大小
	UCHAR			Contents[512];				//保留字段
}FILEDISK_NOTIFICATION, *PFILEDISK_NOTIFICATION;

typedef struct _FILEDISK_REPLY {

	ULONG			fileDiskAuthority;			//应用层返回的权限

} FILEDISK_REPLY, *PFILEDISK_REPLY;


typedef struct _READ_UDISK_CONTEXT_
{
// 	PUNICODE_STRING	DeviceName;
	ULONG			hardDiskNo;				//物理磁盘号
	PWCH			deviceName;
}READ_UDISK_CONTEXT, *PREAD_UDISK_CONTEXT;

FLT_PREOP_CALLBACK_STATUS MiniFilterCommonPreOperationCallback(
	PFLT_CALLBACK_DATA Data,
	PCFLT_RELATED_OBJECTS FltObjects,
	PVOID *CompletionContext
	);


FLT_POSTOP_CALLBACK_STATUS MiniFilterCommonPostOperationCallback(
	PFLT_CALLBACK_DATA Data,
	PCFLT_RELATED_OBJECTS FltObjects,
	PVOID CompletionContext,
	FLT_POST_OPERATION_FLAGS Flags
	);

FLT_PREOP_CALLBACK_STATUS MiniFilterPreShutdownCallback(
	PFLT_CALLBACK_DATA Data,
	PCFLT_RELATED_OBJECTS FltObjects,
	PVOID *CompletionContext
	);

FLT_PREOP_CALLBACK_STATUS MiniFilterPreCreateCallback(
	PFLT_CALLBACK_DATA Data,
	PCFLT_RELATED_OBJECTS FltObjects,
	PVOID *CompletionContext
	);

FLT_POSTOP_CALLBACK_STATUS MiniFilterPostCreateCallback(
	PFLT_CALLBACK_DATA Data,
	PCFLT_RELATED_OBJECTS FltObjects,
	PVOID CompletionContext,
	FLT_POST_OPERATION_FLAGS Flags
	);

FLT_PREOP_CALLBACK_STATUS MiniFilterPreReadCallback(
	PFLT_CALLBACK_DATA Data,
	PCFLT_RELATED_OBJECTS FltObjects,
	PVOID *CompletionContext
	);

FLT_POSTOP_CALLBACK_STATUS MiniFilterPostReadCallback(
	PFLT_CALLBACK_DATA Data,
	PCFLT_RELATED_OBJECTS FltObjects,
	PVOID CompletionContext,
	FLT_POST_OPERATION_FLAGS Flags
	);

FLT_PREOP_CALLBACK_STATUS MiniFilterPreWriteCallback(
	PFLT_CALLBACK_DATA Data,
	PCFLT_RELATED_OBJECTS FltObjects,
	PVOID *CompletionContext
	);

FLT_POSTOP_CALLBACK_STATUS MiniFilterPostWriteCallback(
	PFLT_CALLBACK_DATA Data,
	PCFLT_RELATED_OBJECTS FltObjects,
	PVOID CompletionContext,
	FLT_POST_OPERATION_FLAGS Flags
	);

FLT_PREOP_CALLBACK_STATUS MiniFilterPreCleanUpCallback(
	PFLT_CALLBACK_DATA Data,
	PCFLT_RELATED_OBJECTS FltObjects,
	PVOID *CompletionContext
	);

FLT_POSTOP_CALLBACK_STATUS MiniFilterPostCleanUpCallback(
	PFLT_CALLBACK_DATA Data,
	PCFLT_RELATED_OBJECTS FltObjects,
	PVOID CompletionContext,
	FLT_POST_OPERATION_FLAGS Flags
	);


NTSTATUS
MiniFilterInstanceSetup(
_In_ PCFLT_RELATED_OBJECTS FltObjects,
_In_ FLT_INSTANCE_SETUP_FLAGS Flags,
_In_ DEVICE_TYPE VolumeDeviceType,
_In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
);


NTSTATUS
MiniFilterInstanceQueryTeardown(
_In_ PCFLT_RELATED_OBJECTS FltObjects,
_In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
);

NTSTATUS
MiniFilterUnload(
_In_ FLT_FILTER_UNLOAD_FLAGS Flags
);

//读取磁盘并发送消息的线程
VOID
ReadUDiskThread(
IN PVOID Context
);

VOID
CleanupVolumeContext(
_In_ PFLT_CONTEXT Context,
_In_ FLT_CONTEXT_TYPE ContextType
);

BOOLEAN
Is10MVolume(
IN ULONG hardDiskNo
);

NTSTATUS
MyRtlVolumeDeviceGetPhysicalNumber(
IN PUNICODE_STRING DeviceName,
OUT PULONG PhysicalNumber
);

NTSTATUS
MyRtlVolumeDeviceToDosName(
IN PUNICODE_STRING DeviceName,
OUT PUNICODE_STRING DosName
);


PWCHAR
GetFileAppFullPath(PUNICODE_STRING dosname, USHORT DirLen, PFLT_FILE_NAME_INFORMATION filename);

NTSTATUS
GetOurInstanceFromVolume(
__in PFLT_FILTER  Filter,
__in PFILE_OBJECT FileObject,
__out PFLT_INSTANCE *OutInstance
);


void
TLInspectWorker(
IN PVOID StartContext
);

void DoWriteFile(PBACKE_FILE_RECORD packet);


BOOLEAN
ScannerpCheckExtension(
_In_ PUNICODE_STRING Extension
);

#endif // _MINI_FILTER_
