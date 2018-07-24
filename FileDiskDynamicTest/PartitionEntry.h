#pragma once
#ifndef _PARTITION_ENTRY_
#define _PARTITION_ENTRY_

#include <windows.h>


/*
��ͷ�� = ������
*/

typedef struct _PARTITIONENTRY_
{
	BYTE status;				//statrus or physical drive, old MBRs only accept 0x80, 0x00 means inactive
	struct _STARTCHS_
	{
		BYTE trackNum;		//�ŵ���
		BYTE sectorsNum;	//������
		BYTE cylinderNum;	//�����
	}STARTCHS;
	BYTE type;					//partition type   0x07 NTFS  0x0c FAT32
	struct _ENDCHS_
	{
		BYTE trackNum;		//�ŵ���
		BYTE sectorsNum;	//������
		BYTE cylinderNum;	//�����
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