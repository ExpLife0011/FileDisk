// FileDiskDynamic.cpp : 定义 DLL 应用程序的导出函数。
//
#include "stdafx.h"
#include <stdlib.h>
#include "FileDiskDynamic.h"

HANDLE g_hPort = INVALID_HANDLE_VALUE;

typedef struct _FILEDISK_NOTIFICATION
{
	BYTE			isSpecial;					//是否是特定的U盘
	ULONG			fileDiskAuthority;			//权限
	LARGE_INTEGER	offset;						//U盘偏移
	LARGE_INTEGER	storageSize;				//U盘大小
}FILEDISK_NOTIFICATION, *PFILEDISK_NOTIFICATION;

typedef struct _FILEDISK_NOTIFICATION_MESSAGE {

	//
	//  Required structure header.
	//

	FILTER_MESSAGE_HEADER MessageHeader;


	//
	//  Private scanner-specific fields begin here.
	//

	FILEDISK_NOTIFICATION Notification;


} FILEDISK_NOTIFICATION__MESSAGE, *PFILEDISK_NOTIFICATION__MESSAGE;

typedef struct _FILEDISK_REPLY_MESSAGE_
{
	FILTER_REPLY_HEADER replyHeader;
	FILEDISK_NOTIFICATION reply;
}FILEDISK_REPLY_MESSAGE, *PFILEDISK_REPLY_MESSAGE;

/************************************************************************/
/* 监控是否有U盘插入                                                      */
/************************************************************************/
DWORD WINAPI MessageWorker(IN LPVOID pParam)
{

	HRESULT                          hr = S_OK;
	PFILEDISK_NOTIFICATION            notification = NULL;
	PFILEDISK_NOTIFICATION__MESSAGE   message = NULL;
	FILEDISK_REPLY_MESSAGE           replyMessage = { 0 };

	message = (PFILEDISK_NOTIFICATION__MESSAGE)malloc(sizeof(PFILEDISK_NOTIFICATION__MESSAGE));
	if (NULL == message)
		return 0x0L;

	while (TRUE)
	{
		memset(&(message->Notification), 0, sizeof(message->Notification));

		//
		//  Request messages from the filter driver.
		//
		OutputDebugString(L"***********获取驱动层的消息*************");
		hr = FilterGetMessage(
			g_hPort,
			&message->MessageHeader,
			sizeof(FILEDISK_NOTIFICATION__MESSAGE),
			NULL);

		if (!SUCCEEDED(hr))
		{
			continue;
		}

		replyMessage.replyHeader.Status = 0;
		replyMessage.replyHeader.MessageId = message->MessageHeader.MessageId;

		replyMessage.reply.fileDiskAuthority = 2;


		hr = FilterReplyMessage(
			g_hPort,
			(PFILTER_REPLY_HEADER)&replyMessage,
			sizeof(replyMessage)
			);
		OutputDebugString(L"***********收到并且返回***********");
	}

	if (NULL != message) { free(message); }

	return 1;
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


