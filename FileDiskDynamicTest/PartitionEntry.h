#pragma once
#ifndef _PARTITION_ENTRY_
#define _PARTITION_ENTRY_

#include <windows.h>


/*
磁头数 = 盘面数
*/

typedef struct _PARTITIONENTRY_
{
	BYTE status;				//statrus or physical drive, old MBRs only accept 0x80, 0x00 means inactive
	struct _STARTCHS_
	{
		BYTE trackNum;		//磁道号
		BYTE sectorsNum;	//扇区号
		BYTE cylinderNum;	//柱面号
	}STARTCHS;
	BYTE type;					//partition type   0x07 NTFS  0x0c FAT32
	struct _ENDCHS_
	{
		BYTE trackNum;		//磁道号
		BYTE sectorsNum;	//扇区号
		BYTE cylinderNum;	//柱面号
	}ENDCHS;
	DWORD startLBA;					//LBA of first absolute sector in the partition
	DWORD partitionSize;			//Number of sectors in partition

}PARTITIONENTRY, * PPARTITIONENTRY;


typedef struct _DRIVE_INFO_
{
	ULONGLONG DiskSize;
	ULONGLONG Cylinders;
	DWORD TracksPerCylinder;
	DWORD SectorsPerTrack;
	DWORD BytesPerSector;
}DRIVEINFO, * PDRIVEINFO;


#endif