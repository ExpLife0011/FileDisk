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
BOOL IsSpecialUDisk(char driveLetter);
BOOL QueryDeviceStatus(DWORD DeviceNumber);
DWORD GetAvailableDeviceNumber();
__declspec(dllexport)	BOOL MakeDisk(char DriveLetter);

#ifdef __cplusplus
}
#endif

#endif // !_FILEDISKDYNAMIC_H_

