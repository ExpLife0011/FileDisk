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
	ENUM_AUTHORITY = 0,
	ENUM_EXCEPTPROCESSID,
	ENUM_FORMATTING,
	ENUM_BACKFILEPATH,
	ENUM_BACKFILEEXTENTION				//�ļ���չ��
} NPMINI_COMMAND;

typedef struct _COMMAND_MESSAGE {
	NPMINI_COMMAND 	Command;				//��Ϣ���
	ULONG			commandContext;			//��Ϣ����
	WCHAR			backFilePath[256];		//�ļ���ƴ洢·��
} COMMAND_MESSAGE, *PCOMMAND_MESSAGE;


#ifdef __cplusplus
extern "C" {
#endif

__declspec(dllexport)	int InitialCommunicationPort(void);						//������
__declspec(dllexport)   int FDSendMessage(NPMINI_COMMAND type, PVOID InputBuffer);
__declspec(dllexport)	int FileDiskMount(int DeviceNumber, POPEN_FILE_INFORMATION OpenFileInformation, BOOLEAN CdImage);
__declspec(dllexport)	int FileDiskUmount(char DriveLetter);
__declspec(dllexport)	BOOL IsSpecialUDisk(char driveLetter);
__declspec(dllexport)	BOOL QueryDeviceStatus(DWORD DeviceNumber);
__declspec(dllexport)	DWORD GetAvailableDeviceNumber();
__declspec(dllexport)	BOOL MakeDisk(char DriveLetter);						//�������
__declspec(dllexport)	BOOL SetUDiskAuthority(DWORD Authority);				//���ý��ʵ�Ȩ��
__declspec(dllexport)	BOOL GetUDiskAuthority(PDWORD Authority);				//��ȡ���ʵ�Ȩ��
__declspec(dllexport)   DWORD WINAPI AutoDiskMountThread(IN LPVOID pParam);
__declspec(dllexport)	BOOL SetExceptProcessId(DWORD processId);
__declspec(dllexport)	int CommunicationPort(void);							//�����ӣ������ʹ���Զ�����u�̺�ж�صĻ���ʹ�ô˺���ͨ��
__declspec(dllexport)	BOOL SetFormatStatus(DWORD formatStatus);
__declspec(dllexport)	BOOL SetBackFilePath(PWCHAR	backFilePath);
__declspec(dllexport)	BOOL SetBackFileExtention(PWCHAR backFileExtention);
__declspec(dllexport)	BOOL SetCurrentDeviceStatus(BOOL status);
__declspec(dllexport)	DWORD GetAllDriveLetter(PCHAR driveLetter);				//���ع��صĴ��̸�����driveletter���ش����̷�

BOOL GetAvailableDriveLetter(char * DriverLetter);				//��ȡ���õ��̷������ڹ���u��

#ifdef __cplusplus
}
#endif

#endif // !_FILEDISKDYNAMIC_H_

