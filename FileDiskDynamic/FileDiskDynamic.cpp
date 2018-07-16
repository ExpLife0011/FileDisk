// FileDiskDynamic.cpp : 定义 DLL 应用程序的导出函数。
//
#include "stdafx.h"
#include <stdlib.h>
#include "FileDiskDynamic.h"

HANDLE g_hPort, g_completion = INVALID_HANDLE_VALUE;


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
/* 监控是否有U盘插入                                                      */
/************************************************************************/
// DWORD WINAPI MessageWorker(IN LPVOID pParam)
// {
// 
// 	HRESULT                          hr = S_OK;
// 	PFILEDISK_NOTIFICATION            notification = NULL;
// 	PFILEDISK_MESSAGE				   message = NULL;
// 	FILEDISK_REPLY_MESSAGE           replyMessage = { 0 };
// 
// 	message = (PFILEDISK_MESSAGE)malloc(sizeof(PFILEDISK_MESSAGE));
// 	if (NULL == message)
// 		return 0x0L;
// 
// 	while (TRUE)
// 	{
// 		memset(&(message->Notification), 0, sizeof(message->Notification));
// 
// 		//
// 		//  Request messages from the filter driver.
// 		//
// 		OutputDebugString(L"***********获取驱动层的消息*************");
// 		hr = FilterGetMessage(
// 			g_hPort,
// 			&message->MessageHeader,
// 			FIELD_OFFSET(FILEDISK_MESSAGE, Ovlp),
// 			NULL);
// 
// 		if (!SUCCEEDED(hr))
// 		{
// 			continue;
// 		}
// 
// 		replyMessage.ReplyHeader.Status = 0;
// 		replyMessage.ReplyHeader.MessageId = message->MessageHeader.MessageId;
// 
// 		replyMessage.Reply.fileDiskAuthority = 2;
// 
// 
// 		hr = FilterReplyMessage(
// 			g_hPort,
// 			(PFILTER_REPLY_HEADER)&replyMessage,
// 			sizeof(replyMessage)
// 			);
// 		OutputDebugString(L"***********收到并且返回***********");
// 	}
// 
// 	if (NULL != message) { free(message); }
// 
// 	return 1;
// }


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

			OutputDebugString(L"FilterGetMessage Error\n");

		}

		notification = &message->Notification;

		OutputDebugString((wchar_t *)&notification->Contents);

		replyMessage.ReplyHeader.Status = 0;
		replyMessage.ReplyHeader.MessageId = message->MessageHeader.MessageId;


		replyMessage.Reply.fileDiskAuthority = 2;

		printf("Replying message, fileDiskAuthority: %d\n", replyMessage.Reply.fileDiskAuthority);

// 		hr = FilterReplyMessage(g_hPort,
// 			(PFILTER_REPLY_HEADER)&replyMessage,
// 			sizeof(FILTER_REPLY_HEADER) + sizeof(FILEDISK_REPLY));

		if (SUCCEEDED(hr)) {

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
		else {

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
	PCOMMAND_MESSAGE commandMessage = (PCOMMAND_MESSAGE)InputBuffer;

	hResult = FilterSendMessage(
		g_hPort,
		commandMessage,
		sizeof(COMMAND_MESSAGE),
		NULL,
		NULL,
		&bytesReturned);

	if (hResult != S_OK) {
		return hResult;
	}
	return 0;
}


