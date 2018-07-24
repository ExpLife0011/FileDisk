#include "stdafx.h"
#include <winioctl.h>
//#include <ntddstor.h>

#include "DiskOption.h"

#include <Shlobj.h>
#include "crc32.h"



#define SECTORLENGTH 512


//用来填充0扇区
unsigned char sector0Data[512] = {
	0x33, 0xC0, 0x8E, 0xD0, 0xBC, 0x00, 0x7C, 0x8E, 0xC0, 0x8E, 0xD8, 0xBE, 0x00, 0x7C, 0xBF, 0x00,		//00000000: 3.....|......|..
	0x06, 0xB9, 0x00, 0x02, 0xFC, 0xF3, 0xA4, 0x50, 0x68, 0x1C, 0x06, 0xCB, 0xFB, 0xB9, 0x04, 0x00,		//00000010: .......Ph.......
	0xBD, 0xBE, 0x07, 0x80, 0x7E, 0x00, 0x00, 0x7C, 0x0B, 0x0F, 0x85, 0x0E, 0x01, 0x83, 0xC5, 0x10,		//00000020: ....~..|........
	0xE2, 0xF1, 0xCD, 0x18, 0x88, 0x56, 0x00, 0x55, 0xC6, 0x46, 0x11, 0x05, 0xC6, 0x46, 0x10, 0x00,		//00000030: .....V.U.F...F..
	0xB4, 0x41, 0xBB, 0xAA, 0x55, 0xCD, 0x13, 0x5D, 0x72, 0x0F, 0x81, 0xFB, 0x55, 0xAA, 0x75, 0x09,		//00000040: .A..U..]r...U.u.
	0xF7, 0xC1, 0x01, 0x00, 0x74, 0x03, 0xFE, 0x46, 0x10, 0x66, 0x60, 0x80, 0x7E, 0x10, 0x00, 0x74,		//00000050: ....t..F.f`.~..t
	0x26, 0x66, 0x68, 0x00, 0x00, 0x00, 0x00, 0x66, 0xFF, 0x76, 0x08, 0x68, 0x00, 0x00, 0x68, 0x00,		//00000060: &fh....f.v.h..h.
	0x7C, 0x68, 0x01, 0x00, 0x68, 0x10, 0x00, 0xB4, 0x42, 0x8A, 0x56, 0x00, 0x8B, 0xF4, 0xCD, 0x13,		//00000070: |h..h...B.V.....
	0x9F, 0x83, 0xC4, 0x10, 0x9E, 0xEB, 0x14, 0xB8, 0x01, 0x02, 0xBB, 0x00, 0x7C, 0x8A, 0x56, 0x00,		//00000080: ............|.V.
	0x8A, 0x76, 0x01, 0x8A, 0x4E, 0x02, 0x8A, 0x6E, 0x03, 0xCD, 0x13, 0x66, 0x61, 0x73, 0x1C, 0xFE,		//00000090: .v..N..n...fas..
	0x4E, 0x11, 0x75, 0x0C, 0x80, 0x7E, 0x00, 0x80, 0x0F, 0x84, 0x8A, 0x00, 0xB2, 0x80, 0xEB, 0x84,		//000000A0: N.u..~..........
	0x55, 0x32, 0xE4, 0x8A, 0x56, 0x00, 0xCD, 0x13, 0x5D, 0xEB, 0x9E, 0x81, 0x3E, 0xFE, 0x7D, 0x55,		//000000B0: U2..V...]...>.}U
	0xAA, 0x75, 0x6E, 0xFF, 0x76, 0x00, 0xE8, 0x8D, 0x00, 0x75, 0x17, 0xFA, 0xB0, 0xD1, 0xE6, 0x64,		//000000C0: .un.v....u.....d
	0xE8, 0x83, 0x00, 0xB0, 0xDF, 0xE6, 0x60, 0xE8, 0x7C, 0x00, 0xB0, 0xFF, 0xE6, 0x64, 0xE8, 0x75,		//000000D0: ......`.|....d.u
	0x00, 0xFB, 0xB8, 0x00, 0xBB, 0xCD, 0x1A, 0x66, 0x23, 0xC0, 0x75, 0x3B, 0x66, 0x81, 0xFB, 0x54,		//000000E0: .......f#.u;f..T
	0x43, 0x50, 0x41, 0x75, 0x32, 0x81, 0xF9, 0x02, 0x01, 0x72, 0x2C, 0x66, 0x68, 0x07, 0xBB, 0x00,		//000000F0: CPAu2....r,fh...
	0x00, 0x66, 0x68, 0x00, 0x02, 0x00, 0x00, 0x66, 0x68, 0x08, 0x00, 0x00, 0x00, 0x66, 0x53, 0x66,		//00000100: .fh....fh....fSf
	0x53, 0x66, 0x55, 0x66, 0x68, 0x00, 0x00, 0x00, 0x00, 0x66, 0x68, 0x00, 0x7C, 0x00, 0x00, 0x66,		//00000110: SfUfh....fh.|..f
	0x61, 0x68, 0x00, 0x00, 0x07, 0xCD, 0x1A, 0x5A, 0x32, 0xF6, 0xEA, 0x00, 0x7C, 0x00, 0x00, 0xCD,		//00000120: ah.....Z2...|...
	0x18, 0xA0, 0xB7, 0x07, 0xEB, 0x08, 0xA0, 0xB6, 0x07, 0xEB, 0x03, 0xA0, 0xB5, 0x07, 0x32, 0xE4,		//00000130: ..............2.
	0x05, 0x00, 0x07, 0x8B, 0xF0, 0xAC, 0x3C, 0x00, 0x74, 0x09, 0xBB, 0x07, 0x00, 0xB4, 0x0E, 0xCD,		//00000140: ......<.t.......
	0x10, 0xEB, 0xF2, 0xF4, 0xEB, 0xFD, 0x2B, 0xC9, 0xE4, 0x64, 0xEB, 0x00, 0x24, 0x02, 0xE0, 0xF8,		//00000150: ......+..d..$...
	0x24, 0x02, 0xC3, 0x49, 0x6E, 0x76, 0x61, 0x6C, 0x69, 0x64, 0x20, 0x70, 0x61, 0x72, 0x74, 0x69,		//00000160: $..Invalid parti
	0x74, 0x69, 0x6F, 0x6E, 0x20, 0x74, 0x61, 0x62, 0x6C, 0x65, 0x00, 0x45, 0x72, 0x72, 0x6F, 0x72,		//00000170: tion table.Error
	0x20, 0x6C, 0x6F, 0x61, 0x64, 0x69, 0x6E, 0x67, 0x20, 0x6F, 0x70, 0x65, 0x72, 0x61, 0x74, 0x69,		//00000180:  loading operati
	0x6E, 0x67, 0x20, 0x73, 0x79, 0x73, 0x74, 0x65, 0x6D, 0x00, 0x4D, 0x69, 0x73, 0x73, 0x69, 0x6E,		//00000190: ng system.Missin
	0x67, 0x20, 0x6F, 0x70, 0x65, 0x72, 0x61, 0x74, 0x69, 0x6E, 0x67, 0x20, 0x73, 0x79, 0x73, 0x74,		//000001A0: g operating syst
	0x65, 0x6D, 0x00, 0x00, 0x00, 0x63, 0x7B, 0x9A, 0xAA, 0x51, 0x04, 0x60, 0x00, 0x00, 0x80, 0x20,		//000001B0: em...c{..Q.`... 
	0x21, 0x00, 0x0C, 0xFE, 0xFF, 0xFF, 0x00, 0x08, 0x00, 0x00, 0x00, 0x18, 0xDE, 0x01, 0x00, 0x00,		//000001C0: !...............
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,		//000001D0: ................
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,		//000001E0: ................
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x55, 0xAA 		//000001F0: ..............U.
};



BOOL LockVolum(char letter)
{
	// 1.openvolum  2.lockvolum 3.dismountvolum
	char path[MAX_PATH] = { 0 };
	sprintf(path, "\\\\.\\%c:", letter);
	HANDLE hVolum = CreateFileA(path,
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		FILE_FLAG_NO_BUFFERING,
		NULL);
	if (hVolum == INVALID_HANDLE_VALUE)
	{
// 		CString str;
// 		str.Format(L"dismountvolum createfile fail, error code: %d", GetLastError());
// 		MessageBox(NULL, str, L"error", MB_OK);
		CloseHandle(hVolum);
		return FALSE;
	}

	BOOL ret = FALSE;
	// 	for (int i = 0; i < 20; i++)
	// 	{
	DWORD BytesReturned = 0;
	ret = DeviceIoControl(hVolum,
		FSCTL_LOCK_VOLUME,
		NULL,
		0,
		NULL,
		0,
		&BytesReturned,
		NULL);

	// 		if (ret == FALSE)
	// 		{
	// 
	// 			Sleep(200);
	// 		}
	// 		else
	// 		{
	// 			break;
	// 		}
	// 	}
	if (ret == FALSE)
	{
// 		CString str;
// 		str.Format(L"dismountvolum lock volum fail, error code: %d", GetLastError());
// 		MessageBox(NULL, str, L"error", MB_OK);
		CloseHandle(hVolum);
		return FALSE;
	}

	CloseHandle(hVolum);
	return TRUE;
}


BOOL UnlockVolume(char letter)
{
	char path[MAX_PATH] = { 0 };
	sprintf(path, "\\\\.\\%c:", letter);
	HANDLE hVolum = CreateFileA(path,
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		FILE_FLAG_NO_BUFFERING,
		NULL);

	BOOL ret = DeviceIoControl(hVolum,
		FSCTL_UNLOCK_VOLUME,
		NULL,
		0,
		NULL,
		0,
		NULL,
		NULL);

	if (!ret)
	{
// 		CString str;
// 		str.Format(L"unlock volume fail, error code :%d", GetLastError());
// //		MessageBox(NULL, str, L"error", MB_OK);
		CloseHandle(hVolum);
		return FALSE;
	}
	CloseHandle(hVolum);
	return TRUE;
}


//卸载盘符
BOOL DisMountVolum(char letter)
{
	char path[MAX_PATH] = { 0 };
	sprintf(path, "\\\\.\\%c:", letter);
	HANDLE hVolum = CreateFileA(path,
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		FILE_FLAG_NO_BUFFERING,
		NULL);

	BOOL ret = FALSE;

	DWORD BytesReturned = 0;

	ret = DeviceIoControl(hVolum,
		FSCTL_DISMOUNT_VOLUME,
		NULL,
		0,
		NULL,
		0,
		&BytesReturned,
		NULL);
	if (ret == FALSE)
	{
// 		CString str;
// 		str.Format(L"dismountvolum dismount volum fail, error code: %d", GetLastError());
// 		MessageBox(NULL, str, L"error", MB_OK);
		CloseHandle(hVolum);
		return FALSE;
	}

	CloseHandle(hVolum);
	return TRUE;
}

//开始写磁盘
BOOL WritePhysicalDrive1(int num)
{

	DRIVEINFO driveInfo = { 0 };
	GetPhysicalDriveInfo(num, &driveInfo);

	CHAR path[MAX_PATH] = { 0 };
	sprintf(path, "\\\\.\\PHYSICALDRIVE%d", num);

	HANDLE hDrive = CreateFileA(path,
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		FILE_FLAG_NO_BUFFERING,
		NULL);
	if (hDrive == INVALID_HANDLE_VALUE)
	{
		DWORD errCode = GetLastError();
		CloseHandle(hDrive);
		MessageBoxW(NULL, L"physical drive open failed", L"error", MB_OK);
		return FALSE;
	}

	// 	LARGE_INTEGER bufferLen;
	// 	bufferLen.HighPart = (ULONG)(BUFFERLENGTH >> 32);
	// 	bufferLen.LowPart = (ULONG)(BUFFERLENGTH & 0xFFFFFFFF);


	char buffer[SECTORLENGTH] = { 0 };

	DWORD bytesOfBuffer = 0;
	BOOL ret = FALSE;
	for (int i = 0; i < 2048; i++)
	{

		ULONGLONG byteOffset = SECTORLENGTH * i;

		OVERLAPPED over;
		ZeroMemory(&over, sizeof(OVERLAPPED));
		over.hEvent = NULL;
		over.Offset = 0;
		over.OffsetHigh = 0;

		over.Offset = (ULONG)((byteOffset) & 0xFFFFFFFF);
		over.OffsetHigh = (ULONG)((byteOffset) >> 32);

		if (i == 0)
		{
			PPARTITIONENTRY partitionEntry = (PPARTITIONENTRY)&sector0Data[0x1BE];

			partitionEntry->status = 0x80;
			partitionEntry->STARTCHS.trackNum = (BYTE)(2048 / driveInfo.SectorsPerTrack);							//20
			partitionEntry->STARTCHS.sectorsNum = (BYTE)(2048 % driveInfo.SectorsPerTrack + 1);						//21
			partitionEntry->STARTCHS.cylinderNum = (BYTE)(2048 / (driveInfo.SectorsPerTrack * driveInfo.TracksPerCylinder));//0
			partitionEntry->type = 0x7;
			partitionEntry->ENDCHS.trackNum = 0xFE;
			partitionEntry->ENDCHS.sectorsNum = 0xFF;
			partitionEntry->ENDCHS.cylinderNum = 0xFF;
			partitionEntry->startLBA = 2048;
			partitionEntry->partitionSize = (DWORD)((driveInfo.DiskSize / 512) - 2048);

			ret = WriteFile(hDrive, sector0Data, SECTORLENGTH, &bytesOfBuffer, &over);
			if (!ret)
			{
				CloseHandle(hDrive);
				DWORD errCode = GetLastError();
// 				CString str;
// 				str.Format(L"write 0 sector fail, error code %d", errCode);
// 				MessageBox(NULL, str, L"error", MB_OK);
				return FALSE;
			}
		}
		else
		{
			ret = WriteFile(hDrive, buffer, SECTORLENGTH, &bytesOfBuffer, &over);
			if (!ret)
			{
				CloseHandle(hDrive);
				DWORD errCode = GetLastError();
// 				CString str;
// 				str.Format(L"write other sector fail, error code %d", errCode);
// 				MessageBox(NULL, str, L"error", MB_OK);
				return FALSE;
			}
		}

	}

	CloseHandle(hDrive);

	MessageBoxW(NULL, L"complete disk format", L"notice", MB_OK);

// 	char cmd[MAX_PATH] = { 0 };
// 	sprintf(cmd, "format %c: /FS:NTFS /Q /Y", g_letter);
// 	system(cmd);

	return TRUE;
}

BOOL WritePhysicalDrive(char letter, DWORD num, PDRIVEINFO driveInfo)
{

	char path[MAX_PATH] = { 0 };
	sprintf(path, "\\\\.\\%c:", letter);

	HANDLE hDrive = CreateFileA(path,
		GENERIC_WRITE | GENERIC_READ,
		FILE_SHARE_WRITE | FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_FLAG_NO_BUFFERING,
		NULL);

	if (hDrive == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}

	char buffer[SECTORLENGTH] = { 0 };

	DWORD bytesOfBuffer = 0;
	BOOL ret = FALSE;

		ULONGLONG byteOffset = 0;
		OVERLAPPED over;
		ZeroMemory(&over, sizeof(OVERLAPPED));
		over.hEvent = NULL;
		over.Offset = 0;
		over.OffsetHigh = 0;

		over.Offset = (ULONG)((byteOffset) & 0xFFFFFFFF);
		over.OffsetHigh = (ULONG)((byteOffset) >> 32);


		PPARTITIONENTRY partitionEntry = (PPARTITIONENTRY)&sector0Data[0x1BE];

		partitionEntry->status = 0x80;
		partitionEntry->STARTCHS.trackNum = (BYTE)(2048 / driveInfo->SectorsPerTrack);							//20
		partitionEntry->STARTCHS.sectorsNum = (BYTE)(2048 % driveInfo->SectorsPerTrack + 1);						//21
		partitionEntry->STARTCHS.cylinderNum = (BYTE)(2048 / (driveInfo->SectorsPerTrack * driveInfo->TracksPerCylinder));//0
		partitionEntry->type = 0x7;
		partitionEntry->ENDCHS.trackNum = 0xFE;
		partitionEntry->ENDCHS.sectorsNum = 0xFF;
		partitionEntry->ENDCHS.cylinderNum = 0xFF;
		partitionEntry->startLBA = 2048;
		partitionEntry->partitionSize = (DWORD)((driveInfo->DiskSize / 512) - 2048);

		ret = WriteFile(hDrive, sector0Data, SECTORLENGTH, &bytesOfBuffer, &over);
		if (!ret)
		{
			CloseHandle(hDrive);
			DWORD errCode = GetLastError();
			return FALSE;
		}

		return TRUE;

}

BOOL DiskFormat(char letter)
{
// 	char cmd[MAX_PATH] = { 0 };
// 	sprintf(cmd, "format %c: /FS:NTFS /Q /Y", letter);
// 	system(cmd);

	SHFormatDrive(NULL, letter - 'A', SHFMT_ID_DEFAULT, SHFMT_OPT_FULL);

	return TRUE;
}

//获取磁盘相关信息
BOOL GetPhysicalDriveInfo(DWORD physicalNum, PDRIVEINFO DriveInfo)
{
	char path[MAX_PATH] = { 0 };
	sprintf(path, "\\\\.\\PHYSICALDRIVE%d", physicalNum);
	HANDLE hDrive = CreateFileA(path,
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		FILE_FLAG_NO_BUFFERING,
		NULL);
	if (hDrive == INVALID_HANDLE_VALUE)
	{
// 		CString str;
// 		str.Format(L"Drive info error code : %d", GetLastError());
// 		MessageBox(NULL, str, L"error", MB_OK);
		CloseHandle(hDrive);

		return FALSE;
	}

	DISK_GEOMETRY_EX diskGeometryEx;
	ZeroMemory(&diskGeometryEx, sizeof(DISK_GEOMETRY_EX));
	DWORD byteReturned = 0;
	BOOL ret = DeviceIoControl(hDrive,
		IOCTL_DISK_GET_DRIVE_GEOMETRY_EX,
		NULL,
		0,
		&diskGeometryEx,
		sizeof(DISK_GEOMETRY_EX),
		&byteReturned,
		NULL);
	if (!ret)
	{
// 		CString str;
// 		str.Format(L"Drive info error code: %d", GetLastError());
// 		MessageBox(NULL, str, L"error", MB_OK);
		CloseHandle(hDrive);

		return FALSE;
	}

	ULONGLONG diskSize = diskGeometryEx.DiskSize.QuadPart;
	ULONGLONG cylinders = diskGeometryEx.Geometry.Cylinders.QuadPart;
	DWORD TracksPerCylinder = diskGeometryEx.Geometry.TracksPerCylinder;
	DWORD SectorsPerTrack = diskGeometryEx.Geometry.SectorsPerTrack;
	DWORD BytesPerSector = diskGeometryEx.Geometry.BytesPerSector;

	DriveInfo->DiskSize = diskSize;
	DriveInfo->Cylinders = cylinders;
	DriveInfo->TracksPerCylinder = TracksPerCylinder;
	DriveInfo->SectorsPerTrack = SectorsPerTrack;
	DriveInfo->BytesPerSector = BytesPerSector;

// 	CString str;
// 	str.Format(L"diskSize:%lld\r\ncylinders:%lld\r\nTracksPerCylinder:%ld\r\nSectorsPerTrack:%ld\r\nBytesPerSector:%ld\r\n",
// 		diskSize,
// 		cylinders,
// 		TracksPerCylinder,
// 		SectorsPerTrack,
// 		BytesPerSector);
// 	MessageBox(NULL, str, L"error", MB_OK);
	CloseHandle(hDrive);
	return TRUE;
}

//通过 \\\\.\\X: 获取该盘是否为移动介质  type类型为7为移动硬盘
DWORD GetDriveTypeByBus(const CHAR *drive, WORD *type)
{
	HANDLE hDevice;               // handle to the drive to be examined
	BOOL result;                 // results flag
	DWORD readed;                   // discard results

	STORAGE_DESCRIPTOR_HEADER *pDevDescHeader;
	STORAGE_DEVICE_DESCRIPTOR *pDevDesc;
	DWORD devDescLength;
	STORAGE_PROPERTY_QUERY query;

	hDevice = CreateFileA(
		drive, // drive to open
		GENERIC_READ | GENERIC_WRITE,     // access to the drive
		FILE_SHARE_READ | FILE_SHARE_WRITE, //share mode
		NULL,             // default security attributes
		OPEN_EXISTING,    // disposition
		0,                // file attributes
		NULL            // do not copy file attribute
	);
	if (hDevice == INVALID_HANDLE_VALUE) // cannot open the drive
	{
		fprintf(stderr, "CreateFile() Error: %ld\n", GetLastError());
		return DWORD(-1);
	}

	query.PropertyId = StorageDeviceProperty;
	query.QueryType = PropertyStandardQuery;

	pDevDescHeader = (STORAGE_DESCRIPTOR_HEADER *)malloc(sizeof(STORAGE_DESCRIPTOR_HEADER));
	if (NULL == pDevDescHeader)
	{
		return (DWORD)-1;
	}

	result = DeviceIoControl(
		hDevice,     // device to be queried
		IOCTL_STORAGE_QUERY_PROPERTY,     // operation to perform
		&query,
		sizeof(query),               // no input buffer
		pDevDescHeader,
		sizeof(STORAGE_DESCRIPTOR_HEADER),     // output buffer
		&readed,                 // # bytes returned
		NULL);      // synchronous I/O
	if (!result)        //fail
	{
		fprintf(stderr, "IOCTL_STORAGE_QUERY_PROPERTY Error: %ld\n", GetLastError());
		free(pDevDescHeader);
		(void)CloseHandle(hDevice);
		return DWORD(-1);
	}

	devDescLength = pDevDescHeader->Size;
	pDevDesc = (STORAGE_DEVICE_DESCRIPTOR *)malloc(devDescLength);
	if (NULL == pDevDesc)
	{
		free(pDevDescHeader);
		return (DWORD)-1;
	}

	result = DeviceIoControl(
		hDevice,     // device to be queried
		IOCTL_STORAGE_QUERY_PROPERTY,     // operation to perform
		&query,
		sizeof(query),               // no input buffer
		pDevDesc,
		devDescLength,     // output buffer
		&readed,                 // # bytes returned
		NULL);      // synchronous I/O
	if (!result)        //fail
	{
		fprintf(stderr, "IOCTL_STORAGE_QUERY_PROPERTY Error: %ld\n", GetLastError());
		free(pDevDescHeader);
		free(pDevDesc);
		(void)CloseHandle(hDevice);
		return DWORD(-1);
	}

	//printf("%d\n", pDevDesc->BusType);
	*type = (WORD)pDevDesc->BusType;
	free(pDevDescHeader);
	free(pDevDesc);

	(void)CloseHandle(hDevice);
	return 0;
}


// 获取所有驱动器  返回驱动器数组
BOOL GetAllDrive(char * letterList, DWORD * count)
{
	char buffer[MAX_PATH] = { 0 };
	//	char letterList[MAX_PATH] = { 0 };
	DWORD retValue = GetLogicalDriveStringsA(MAX_PATH, buffer);
	if (!retValue)
	{
// 		CString str;
// 		str.Format(L"GetLogicalDriveString fail,error code: %d", GetLastError());
// 		MessageBox(NULL, str, L"error", MB_OK);
		return FALSE;
	}


	char * ptr = buffer;
	int i = 0;
	while (*ptr)
	{
		letterList[i] = *ptr;
		i++;

		ptr += strlen(ptr) + 1;
	}

	*count = i;

// 	CString str;
// 	str.Format(L"%c %c %c %c %c %c", letterList[0], letterList[1], letterList[2], letterList[3], letterList[4], letterList[5]);
// 	MessageBox(NULL, str, L"notice", MB_OK);
	return TRUE;
}



BOOL GetPhysicalNum(char letter, DWORD * num)
{
	CHAR path[MAX_PATH] = {0};
	sprintf(path, "\\\\.\\%c:", letter);

	HANDLE hDevice = CreateFileA(path,
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		FILE_FLAG_NO_BUFFERING,
		NULL);
	if (hDevice == INVALID_HANDLE_VALUE)
	{
		DWORD errCode = GetLastError();
		MessageBoxW(NULL, L"can not createfile", L"error", MB_OK);
		return FALSE;
	}

	STORAGE_DEVICE_NUMBER number;
	DWORD byteOfRead = 0;
	BOOL result = DeviceIoControl(hDevice,
		IOCTL_STORAGE_GET_DEVICE_NUMBER,
		NULL,
		0,
		&number,
		sizeof(number),
		&byteOfRead,
		NULL);

	if (!result)
	{
		MessageBoxW(NULL, L"get device number error", L"error", MB_OK);
		return FALSE;
	}
// 	CString strNum;
// 	strNum.Format(L"device number: %d", number.DeviceNumber);
// 	MessageBox(NULL, strNum, L"notice", MB_OK);

	CloseHandle(hDevice);

	*num = number.DeviceNumber;

	return TRUE;
}



DWORD GetPartitionLetterFromPhysicalDrive(DWORD phyDriveNumber, CHAR **letters)
{
	DWORD mask;
	DWORD driveType;
	DWORD bmLetters;
	DWORD diskNumber;
	CHAR path[MAX_PATH];
	CHAR letter;
	DWORD letterNum;
	WORD i;
	CHAR *p;

	bmLetters = GetLogicalDrives();
	if (0 == bmLetters)
	{
		return (DWORD)-1;
	}

	letterNum = 0;
	for (i = 0; i < sizeof(DWORD) * 8; i++)
	{
		mask = 0x1u << i;
		if ((mask & bmLetters) == 0)        //get one letter
		{
			continue;
		}
		letter = (CHAR)(0x41 + i);    //ASCII change
		sprintf(path, "%c:\\", letter);
		driveType = GetDriveTypeA(path);
		if (driveType != DRIVE_FIXED)
		{
			bmLetters &= ~mask;     //clear this bit
			continue;
		}
		diskNumber = GetPhysicalDriveFromPartitionLetter(letter);
//		GetPhysicalNum(letter, &diskNumber);
		if (diskNumber != phyDriveNumber)
		{
			bmLetters &= ~mask;     //clear this bit
			continue;
		}
		letterNum++;
	}

	//build the result
	*letters = (CHAR *)malloc(letterNum);
	if (NULL == *letters)
	{
		return (DWORD)-1;
	}
	p = *letters;
	for (i = 0; i < sizeof(DWORD) * 8; i++)
	{
		mask = 0x1u << i;
		if ((mask & bmLetters) == 0)
		{
			continue;
		}
		letter = (CHAR)(0x41 + i);    //ASCII change
		*p = letter;
		p++;
	}

	return letterNum;
}



DWORD GetPhysicalDriveFromPartitionLetter(CHAR letter)
{
	HANDLE hDevice;               // handle to the drive to be examined
	BOOL result;                 // results flag
	DWORD readed;                   // discard results
	STORAGE_DEVICE_NUMBER number;   //use this to get disk numbers

	CHAR path[MAX_PATH];
	sprintf(path, "\\\\.\\%c:", letter);
	hDevice = CreateFileA(path, // drive to open
		GENERIC_READ | GENERIC_WRITE,    // access to the drive
		FILE_SHARE_READ | FILE_SHARE_WRITE,    //share mode
		NULL,             // default security attributes
		OPEN_EXISTING,    // disposition
		0,                // file attributes
		NULL);            // do not copy file attribute
	if (hDevice == INVALID_HANDLE_VALUE) // cannot open the drive
	{
		fprintf(stderr, "CreateFile() Error: %ld\n", GetLastError());
		return DWORD(-1);
	}

	result = DeviceIoControl(
		hDevice,                // handle to device
		IOCTL_STORAGE_GET_DEVICE_NUMBER, // dwIoControlCode
		NULL,                            // lpInBuffer
		0,                               // nInBufferSize
		&number,           // output buffer
		sizeof(number),         // size of output buffer
		&readed,       // number of bytes returned
		NULL      // OVERLAPPED structure
	);
	if (!result) // fail
	{
		fprintf(stderr, "IOCTL_STORAGE_GET_DEVICE_NUMBER Error: %ld\n", GetLastError());
		(void)CloseHandle(hDevice);
		return (DWORD)-1;
	}
	//printf("%d %d %d\n\n", number.DeviceType, number.DeviceNumber, number.PartitionNumber);

	(void)CloseHandle(hDevice);
	return number.DeviceNumber;
}


//获取物理磁盘上的所有分区
BOOL GetLetterFromPhysicalDrive(DWORD physicalDriveNumber, CHAR * letterList, DWORD * count)
{
	CHAR allLetterList[MAX_PATH] = { 0 };
	DWORD countOfLetters = 0;
	GetAllDrive(allLetterList, &countOfLetters);

	int j = 0;
	for (int i = 0; i < countOfLetters; i++)
	{
		DWORD phyNum = 0;
		GetPhysicalNum(allLetterList[i], &phyNum);
		if (phyNum == physicalDriveNumber)
		{
			letterList[j] = allLetterList[i];
			j++;
		}
	}
	*count = j;
	return TRUE;
}

DWORD DestroyDisk(DWORD physicalDriveNumber)
{
	HANDLE hDevice;               // handle to the drive to be examined
	BOOL result;                  // results flag
	DWORD readed;                 // discard results
	CHAR diskPath[MAX_PATH];

	sprintf(diskPath, "\\\\.\\PhysicalDrive%d", physicalDriveNumber);

	hDevice = CreateFileA(
		diskPath, // drive to open
		GENERIC_READ | GENERIC_WRITE,     // access to the drive
		FILE_SHARE_READ | FILE_SHARE_WRITE, //share mode
		NULL,             // default security attributes
		OPEN_EXISTING,    // disposition
		0,                // file attributes
		NULL            // do not copy file attribute
	);
	if (hDevice == INVALID_HANDLE_VALUE) // cannot open the drive
	{
// 		CString str;
// 		str.Format(L"destroy disk createfile error code :%d", GetLastError());
// 		MessageBox(NULL, str, L"error", MB_OK);
		//fprintf(stderr, "CreateFile() Error: %ld\n", GetLastError());
		return DWORD(-1);
	}

	result = DeviceIoControl(
		hDevice,               // handle to device
		IOCTL_DISK_DELETE_DRIVE_LAYOUT, // dwIoControlCode
		NULL,                           // lpInBuffer
		0,                              // nInBufferSize
		NULL,                           // lpOutBuffer
		0,                              // nOutBufferSize
		&readed,      // number of bytes returned
		NULL        // OVERLAPPED structure
	);
	if (!result)
	{
// 		CString str;
// 		str.Format(L"destroy disk disk delete drive layout error code :%d", GetLastError());
// 		MessageBox(NULL, str, L"error", MB_OK);
		//fprintf(stderr, "IOCTL_DISK_DELETE_DRIVE_LAYOUT Error: %ld\n", GetLastError());
		(void)CloseHandle(hDevice);
		return DWORD(-1);
	}

	//fresh the partition table
	result = DeviceIoControl(
		hDevice,
		IOCTL_DISK_UPDATE_PROPERTIES,
		NULL,
		0,
		NULL,
		0,
		&readed,
		NULL
	);
	if (!result)
	{
// 		CString str;
// 		str.Format(L"destroy disk disk update properties error code :%d", GetLastError());
// 		MessageBox(NULL, str, L"error", MB_OK);
		fprintf(stderr, "IOCTL_DISK_UPDATE_PROPERTIES Error: %ld\n", GetLastError());
		(void)CloseHandle(hDevice);
		return DWORD(-1);
	}

	(void)CloseHandle(hDevice);
	return 0;
}



BOOL HaveReserveSectors(DWORD physicalDriveNumber)
{
	CHAR path[MAX_PATH] = { 0 };
	sprintf(path, "\\\\.\\PHYSICALDRIVE%d", physicalDriveNumber);

	HANDLE hDrive = CreateFileA(path,
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_WRITE | FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_FLAG_NO_BUFFERING,
		NULL);
	if (hDrive == INVALID_HANDLE_VALUE)
	{
// 		CString str;
// 		str.Format(L"reserve sector create file error, errcode : %d", GetLastError());
// 		MessageBox(NULL, str, L"error", MB_OK);
		return FALSE;
	}

	char buffer[SECTORLENGTH] = { 0 };
	DWORD readReturn = 0;
	BOOL ret = ReadFile(hDrive, buffer, SECTORLENGTH, &readReturn, NULL);
	if (!ret)
	{
// 		CString str;
// 		str.Format(L"reserve sector read file error, errcode:%d", GetLastError());
// 		MessageBox(NULL, str, L"error", MB_OK);
		CloseHandle(hDrive);
		return FALSE;
	}

	char * str = buffer + 3;

	//0扇区 开始的第三个字节开始  可以判断文件系统

//	MessageBoxA(NULL, str, "111", MB_OK);

	if ((BYTE)buffer[510] == 0x55 && (BYTE)buffer[511] == 0xAA)
	{
		if (strncmp(str, "NTFS", 4) == 0 && (BYTE)buffer[510] == 0x55 && (BYTE)buffer[511] == 0xAA)
		{
			CloseHandle(hDrive);
			return FALSE;
		}
		else if (strncmp(str, "MSDOS5.0", 8) == 0 && (BYTE)buffer[510] == 0x55 && (BYTE)buffer[511] == 0xAA)
		{
			CloseHandle(hDrive);
			return FALSE;
		}
		CloseHandle(hDrive);
		return TRUE;
	}
	else
	{
		//如果不是的话，说明被加密
		CloseHandle(hDrive);
		return FALSE;
	}

}



BOOL WriteSpecialUDisk(char letter, DWORD num, PDRIVEINFO driveInfo)
{
	char path[MAX_PATH] = { 0 };
	sprintf(path, "\\\\.\\%c:", letter);

	HANDLE hDrive = CreateFileA(path,
		GENERIC_WRITE | GENERIC_READ,
		FILE_SHARE_WRITE | FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_FLAG_NO_BUFFERING,
		NULL);

	if (hDrive == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}

	BYTE buffer[SECTORLENGTH] = { 0 };

	DWORD bytesOfBuffer = 0;
	BOOL ret = FALSE;

	ULONGLONG byteOffset = 0;
	OVERLAPPED over = {0};
	ZeroMemory(&over, sizeof(OVERLAPPED));
	over.hEvent = NULL;
	over.Offset = 0;
	over.OffsetHigh = 0;

	over.Offset = (ULONG)((byteOffset)& 0xFFFFFFFF);
	over.OffsetHigh = (ULONG)((byteOffset) >> 32);

	// 		if (i == 0)
	// 		{
	PPARTITIONENTRY partitionEntry = (PPARTITIONENTRY)&sector0Data[0x1BE];

	partitionEntry->status = 0x80;
	partitionEntry->STARTCHS.trackNum = (BYTE)(2048 / driveInfo->SectorsPerTrack);							//20
	partitionEntry->STARTCHS.sectorsNum = (BYTE)(2048 % driveInfo->SectorsPerTrack + 1);						//21
	partitionEntry->STARTCHS.cylinderNum = (BYTE)(2048 / (driveInfo->SectorsPerTrack * driveInfo->TracksPerCylinder));//0
	partitionEntry->type = 0x7;
	partitionEntry->ENDCHS.trackNum = 0xFE;
	partitionEntry->ENDCHS.sectorsNum = 0xFF;
	partitionEntry->ENDCHS.cylinderNum = 0xFF;
	partitionEntry->startLBA = 2048;
	partitionEntry->partitionSize = (DWORD)(10 * 1024 * 1024 / 512); //10M大小

	ret = WriteFile(hDrive, sector0Data, SECTORLENGTH, &bytesOfBuffer, &over);    //写0扇区
	if (!ret)
	{
		CloseHandle(hDrive);
		DWORD errCode = GetLastError();

		return FALSE;
	}


	for (int i = 0; i < SECTORLENGTH - 4; i++)
	{
		buffer[i] = rand() / 0xFF;
	}


	DWORD verifyCode = crc32(buffer, 508);
	PFILEDISK_VERIFY filedisk_verify = (PFILEDISK_VERIFY)buffer;
	filedisk_verify->verifyCode = verifyCode;

	ZeroMemory(&over, sizeof(OVERLAPPED));
	over.hEvent = NULL;
	over.Offset = 0;
	over.OffsetHigh = 0;

	byteOffset = (partitionEntry->startLBA + partitionEntry->partitionSize) * 512;

	over.Offset = (ULONG)((byteOffset)& 0xFFFFFFFF);
	over.OffsetHigh = (ULONG)((byteOffset) >> 32);

	ret = WriteFile(hDrive, buffer, SECTORLENGTH, &bytesOfBuffer, &over);    //写0扇区
	if (!ret)
	{
		CloseHandle(hDrive);
		DWORD errCode = GetLastError();

		return FALSE;
	}

	return TRUE;

}