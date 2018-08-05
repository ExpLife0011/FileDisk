#include <windows.h>
#include <stdio.h>
#define _UNICODE 1
#include "tchar.h"


//// Output command
//typedef struct
//{
//	DWORD Lines;
//	PCHAR Output;
//} TEXTOUTPUT, *PTEXTOUTPUT;
//
//// Callback command types
//typedef enum
//{
//	PROGRESS,
//	DONEWITHSTRUCTURE,
//	UNKNOWN2,
//	UNKNOWN3,
//	UNKNOWN4,
//	UNKNOWN5,
//	INSUFFICIENTRIGHTS,
//	UNKNOWN7,
//	UNKNOWN8,
//	UNKNOWN9,
//	UNKNOWNA,
//	DONE,
//	UNKNOWNC,
//	UNKNOWND,
//	OUTPUT,
//	STRUCTUREPROGRESS
//} CALLBACKCOMMAND;
//
//// FMIFS callback definition
//typedef BOOLEAN(__stdcall *PFMIFSCALLBACK)(CALLBACKCOMMAND Command, DWORD SubAction, PVOID ActionInfo);
//
//
//// Chkdsk command in FMIFS
//typedef VOID(__stdcall *PCHKDSK)(PWCHAR DriveRoot,
//	PWCHAR Format,
//	BOOL CorrectErrors,
//	BOOL Verbose,
//	BOOL CheckOnlyIfDirty,
//	BOOL ScanDrive,
//	PVOID Unused2,
//	PVOID Unused3,
//	PFMIFSCALLBACK Callback);
//
//
//// media flags
//#define FMIFS_HARDDISK 0xC
//#define FMIFS_FLOPPY   0x8
//// Format command in FMIFS
//typedef VOID(__stdcall *PFORMATEX)(PWCHAR DriveRoot,
//	DWORD MediaFlag,
//	PWCHAR Format,
//	PWCHAR Label,
//	BOOL QuickFormat,
//	DWORD ClusterSize,
//	PFMIFSCALLBACK Callback);
//
//
//BOOLEAN __stdcall FormatExCallback(CALLBACKCOMMAND Command, DWORD Modifier, PVOID Argument)
//{
//	PDWORD percent;
//	PTEXTOUTPUT output;
//	PBOOLEAN status;
//// 	static createStructures = FALSE;
//
//	// 
//	// We get other types of commands, but we don't have to pay attention to them
//	//
//	switch (Command) {
//
//	case PROGRESS:
//		percent = (PDWORD)Argument;
//		fprintf(stdout, "%d percent completed.\r", *percent);
//		break;
//
//	case OUTPUT:
//		output = (PTEXTOUTPUT)Argument;
//		fprintf(stdout, "%s", output->Output);
//		break;
//
//	case DONE:
//		status = (PBOOLEAN)Argument;
//		if (*status == FALSE) {
//
//			fprintf(stdout, "FormatEx was unable to complete successfully.\n\n");
//// 			Error = TRUE;
//		}
//		break;
//	}
//	return TRUE;
//}
//
//
//HMODULE ifsModule = NULL;
//PFORMATEX FormatEx = NULL;
//
////获取fsifs.dll中的格式化函数指针
//BOOLEAN LoadFMIFSEntryPoints()
//{
//	ifsModule = LoadLibrary(L"fmifs.dll");
//	FormatEx = (PFORMATEX)GetProcAddress(ifsModule, "FormatEx");
//	if (FormatEx == NULL)
//	{
//		return FALSE;
//	}
//
//	return TRUE;
//}
//
//// 调用格式化函数
//int CallFormatDriver(WCHAR *szDriver)
//{
//
//	BOOL    QuickFormat = TRUE;
//	DWORD    ClusterSize = 4096;
//	PWCHAR    Label = NULL;
//	PWCHAR    Format = L"NTFS";
//
//	WCHAR  RootDirectory[MAX_PATH] = { 0 };
//
//// 	wcscpy(RootDirectory, A2W(szDriver));
//	RootDirectory[0] = szDriver[0];
//	RootDirectory[1] = L':';
//	RootDirectory[2] = L'\\';
//	RootDirectory[3] = (WCHAR)0;
//	DWORD media;
//	DWORD driveType;
//	driveType = GetDriveTypeW(RootDirectory);
//	if (driveType != DRIVE_FIXED)
//		media = FMIFS_FLOPPY;
//	if (driveType == DRIVE_FIXED)
//		media = FMIFS_HARDDISK;
//	if (!LoadFMIFSEntryPoints())
//	{
//		return -1;
//	}
//	FormatEx(RootDirectory, media, Format, Label, QuickFormat, ClusterSize, FormatExCallback);
//	FreeLibrary(ifsModule);
//	return 0;
//}
//
//int main()
//{
//	WCHAR letter[1] = { L'G' };
//	CallFormatDriver(letter);
//	return 0;
//}


//======================================================================
//
// Fmifs.h
//
//======================================================================

//
// Output command
//
typedef struct {
	DWORD Lines;
	PCHAR Output;
} TEXTOUTPUT, *PTEXTOUTPUT;

//
// Callback command types
//
typedef enum {
	PROGRESS,
	DONEWITHSTRUCTURE,
	UNKNOWN2,
	UNKNOWN3,
	UNKNOWN4,
	UNKNOWN5,
	INSUFFICIENTRIGHTS,
	UNKNOWN7,
	UNKNOWN8,
	UNKNOWN9,
	UNKNOWNA,
	DONE,
	UNKNOWNC,
	UNKNOWND,
	OUTPUT,
	STRUCTUREPROGRESS
} CALLBACKCOMMAND;

//
// FMIFS callback definition
//
typedef BOOLEAN(__stdcall *PFMIFSCALLBACK)(CALLBACKCOMMAND Command, DWORD SubAction, PVOID ActionInfo);

//
// Chkdsk command in FMIFS
//
typedef VOID(__stdcall *PCHKDSK)(PWCHAR DriveRoot,
	PWCHAR Format,
	BOOL CorrectErrors,
	BOOL Verbose,
	BOOL CheckOnlyIfDirty,
	BOOL ScanDrive,
	PVOID Unused2,
	PVOID Unused3,
	PFMIFSCALLBACK Callback);

//
// Format command in FMIFS
//

// media flags
#define FMIFS_HARDDISK 0xC
#define FMIFS_FLOPPY 0x8

typedef VOID(__stdcall *PFORMATEX)(PWCHAR DriveRoot,
	DWORD MediaFlag,
	PWCHAR Format,
	PWCHAR Label,
	BOOL QuickFormat,
	DWORD ClusterSize,
	PFMIFSCALLBACK Callback);

//
// Enable/Disable volume compression
//
typedef BOOLEAN(__stdcall *PENABLEVOLUMECOMPRESSION)(PWCHAR DriveRoot,
	BOOL Enable);
//////////////////////////////////////////////////////////////////////////



BOOL Error = FALSE;

BOOL QuickFormat = TRUE;
DWORD ClusterSize = 4096;
BOOL CompressDrive = FALSE;
BOOL GotALabel = FALSE;
PWCHAR Label = L"";
PWCHAR Drive = NULL;
PWCHAR Format = L"NTFS";

WCHAR RootDirectory[MAX_PATH] = { 0 };
WCHAR LabelString[12];

PFORMATEX FormatEx;
PENABLEVOLUMECOMPRESSION EnableVolumeCompression;

typedef struct {
	WCHAR SizeString[16];
	DWORD ClusterSize;
} SIZEDEFINITION, *PSIZEDEFINITION;

SIZEDEFINITION LegalSizes[] = {
	{ L"512", 512 },
	{ L"1024", 1024 },
	{ L"2048", 2048 },
	{ L"4096", 4096 },
	{ L"8192", 8192 },
	{ L"16K", 16384 },
	{ L"32K", 32768 },
	{ L"64K", 65536 },
	{ L"128K", 65536 * 2 },
	{ L"256K", 65536 * 4 },
	{ L"", 0 },
};

//----------------------------------------------------------------------
//
// FormatExCallback
//
// The file system library will call us back with commands that we
// can interpret. If we wanted to halt the chkdsk we could return FALSE.
//
//----------------------------------------------------------------------
BOOLEAN __stdcall FormatExCallback(CALLBACKCOMMAND Command, DWORD Modifier, PVOID Argument)
{
	PDWORD percent;
	PTEXTOUTPUT output;
	PBOOLEAN status;
// 	static createStructures = FALSE;

	// 
	// We get other types of commands, but we don't have to pay attention to them
	//
	switch (Command) {

	case PROGRESS:
		percent = (PDWORD)Argument;
		_tprintf(L"%d percent completed.\r", *percent);
		break;

	case OUTPUT:
		output = (PTEXTOUTPUT)Argument;
		fprintf(stdout, "%s", output->Output);
		break;

	case DONE:
		status = (PBOOLEAN)Argument;
		if (*status == FALSE) {

			_tprintf(L"FormatEx was unable to complete successfully.\n\n");
			Error = TRUE;
		}
		break;
	}
	return TRUE;
}

//----------------------------------------------------------------------
//
// LoadFMIFSEntryPoints
//
// Loads FMIFS.DLL and locates the entry point(s) we are going to use
//
//----------------------------------------------------------------------
BOOLEAN LoadFMIFSEntryPoints()
{
	LoadLibraryA("fmifs.dll");

	if (!(FormatEx = (PFORMATEX)GetProcAddress(GetModuleHandleA("fmifs.dll"),
		"FormatEx"))) {

		return FALSE;
	}

	if (!(EnableVolumeCompression = (PENABLEVOLUMECOMPRESSION)GetProcAddress(GetModuleHandleA("fmifs.dll"),
		"EnableVolumeCompression"))) {

		return FALSE;
	}
	return TRUE;
}

int main(int argc, WCHAR *argv[])
{
// 	if (argv[1][1] != L':') return 0;
// 	Drive = argv[1];
// 
// 	wcscpy(RootDirectory, Drive);
	RootDirectory[0] = L'G';
	RootDirectory[1] = L':';
	RootDirectory[2] = L'\\';
	RootDirectory[3] = (WCHAR)0;

	DWORD media;
	DWORD driveType;

	driveType = GetDriveTypeW(RootDirectory);

	if (driveType != DRIVE_FIXED)
		media = FMIFS_FLOPPY;
	if (driveType == DRIVE_FIXED)
		media = FMIFS_HARDDISK;


	//
	// Get function pointers
	//
	if (!LoadFMIFSEntryPoints()) {

		_tprintf(L"Could not located FMIFS entry points.\n\n");
		return -1;
	}

	FormatEx(RootDirectory, media, Format, Label, QuickFormat,
		ClusterSize, FormatExCallback);

	return 0;
}