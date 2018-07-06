// FileDiskDynamic.cpp : 定义 DLL 应用程序的导出函数。
//
#include "stdafx.h"
#include "FileDiskDynamic.h"

HANDLE g_hPort = INVALID_HANDLE_VALUE;

/************************************************************************/
/* 监控是否有U盘插入                                                      */
/************************************************************************/
DWORD MessageWorker(IN LPVOID pParam)
{

	HRESULT                          hr = S_OK;
	PDVCLOCK_NOTIFICATION            notification = NULL;
	PDVCLOCK_NOTIFICATION__MESSAGE   message = NULL;
	DVCLOCK__REPLY_MESSAGE           replyMessage = { 0 };

	message = (PDVCLOCK_NOTIFICATION__MESSAGE)malloc(sizeof(DVCLOCK_NOTIFICATION__MESSAGE));
	if (NULL == message)
		return 0x0L;

	while (TRUE)
	{
		memset(&(message->Notification), 0, sizeof(message->Notification));
		memset(&message->Ovlp, 0, sizeof(OVERLAPPED));

		//
		//  Request messages from the filter driver.
		//

		hr = FilterGetMessage(
			g_hPort,
			&message->MessageHeader,
			FIELD_OFFSET(DVCLOCK_NOTIFICATION__MESSAGE, Ovlp),
			NULL);

		if (!SUCCEEDED(hr))
		{
			continue;
		}

		replyMessage.ReplyHeader.Status = 0;
		replyMessage.ReplyHeader.MessageId = message->MessageHeader.MessageId;
		if (0xFFFFFFFF == WTSGetActiveConsoleSessionId())
		{
			replyMessage.Reply.ErrorStatus = SESSION_ERROR;
		}
		else{
			if (NULL != g_FindRemovableMedia)
				g_FindRemovableMedia(&message->Notification, &replyMessage.Reply);
		}

		hr = FilterReplyMessage(
			g_DeviceLockPortHandle,
			(PFILTER_REPLY_HEADER)&replyMessage,
			sizeof(replyMessage)
			);
	}

	if (NULL != message) { free(message); }

	return 1;
}


extern "C" __declspec(dllexport) int InitialCommunicationPort(void)
{
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


