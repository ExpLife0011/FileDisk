// FileDiskDynamic.cpp : 定义 DLL 应用程序的导出函数。
//
#include "stdafx.h"
#include "FileDiskDynamic.h"

HANDLE g_hPort = INVALID_HANDLE_VALUE;

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

extern "C" __declspec(dllexport) int NPSendMessage(PVOID InputBuffer)
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


