#ifndef _MINI_FILTER_
#define _MINI_FILTER_

#include <fltKernel.h>
#include <ntddk.h>


#define MINI_FILTER

#define FILEDISK_WRITE_AUTHORITY	0x00000002			//дȨ�ޣ�������
#define	FILEDISK_READ_AUTHORITY		0x00000001			//��Ȩ��
#define FILEDISK_NONE_AUTHORITY		0x00000000			//��Ȩ�ޣ�����


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


#endif // _MINI_FILTER_