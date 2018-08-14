#ifndef _FILEDISKDYNAMIC_H_
#define _FILEDISKDYNAMIC_H_

#include <windows.h>
#include <stdio.h>
#include <FltUser.h>
#include "filedisk.h"

// #pragma comment(lib, "user32.lib")
// #pragma comment(lib, "kernel32.lib")
// #pragma comment(lib, "fltLib.lib")
// #pragma comment(lib, "fltMgr.lib")
// #pragma comment(lib, "ntoskrnl.lib")
// #pragma comment(lib, "hal.lib")


#define NPMINI_NAME            L"NPminifilter"
#define NPMINI_PORT_NAME       L"\\NPMiniPort"

typedef enum _NPMINI_COMMAND {
	ENUM_PASS = 0,
	ENUM_BLOCK
} NPMINI_COMMAND;

typedef struct _COMMAND_MESSAGE {
	NPMINI_COMMAND 	Command;
} COMMAND_MESSAGE, *PCOMMAND_MESSAGE;


#ifdef __cplusplus
extern "C" {
#endif

__declspec(dllexport)	int InitialCommunicationPort(void);
__declspec(dllexport)   int FDSendMessage(PVOID InputBuffer);
__declspec(dllexport)	int FileDiskMount(int DeviceNumber, POPEN_FILE_INFORMATION OpenFileInformation, BOOLEAN CdImage);
__declspec(dllexport)	int FileDiskUmount(char DriveLetter);
__declspec(dllexport)	BOOL IsSpecialUDisk(char driveLetter);
__declspec(dllexport)	BOOL QueryDeviceStatus(DWORD DeviceNumber);
__declspec(dllexport)	DWORD GetAvailableDeviceNumber();
__declspec(dllexport)	BOOL MakeDisk(char DriveLetter);						//这个弃用
__declspec(dllexport)	BOOL SetUDiskAuthority(DWORD Authority);				//设置介质的权限
__declspec(dllexport)	BOOL GetUDiskAuthority(PDWORD Authority);				//获取介质的权限
__declspec(dllexport)   DWORD WINAPI AutoDiskMountThread(IN LPVOID pParam);
#ifdef __cplusplus
}
#endif

#endif // !_FILEDISKDYNAMIC_H_

