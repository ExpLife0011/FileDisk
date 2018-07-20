#pragma once
#ifndef _DISKOPTION_
#define _DISKOPTION_

#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#include "PartitionEntry.h"


// 获取所有驱动器
BOOL GetAllDrive(char * letterList, DWORD * count);

//通过 \\\\.\\X: 获取该盘是否为移动介质  type类型为7为移动硬盘
DWORD GetDriveTypeByBus(const CHAR *drive, WORD *type);


//获取磁盘相关信息   输入物理磁盘号   \\\\.\\PHYSICALDRIVE0
// disksize   磁盘大小 -------------|
// cylinders  柱面 -----------------|
// TracksPerCylinder  每柱面磁道数 --|	DriveInfo
// SectorsPerTrack   每磁道扇区数 ---|
// BytePerSector    每扇区字节数 ----|
BOOL GetPhysicalDriveInfo(DWORD physicalNum, PDRIVEINFO DriveInfo);


//开始写磁盘  通过物理磁盘号
//主要功能是在0扇区构造MBR，并将其后的2047个扇区清空  -----弃用
BOOL WritePhysicalDrive1(int num); 


//开始写磁盘  通过物理磁盘号
//主要功能是在0扇区构造MBR，并将其后的2047个扇区清空 
BOOL WritePhysicalDrive(char letter, DWORD num, PDRIVEINFO driveInfo);

//开始写磁盘  磁盘分区只写10M大小
BOOL WriteSpecialUDisk(char letter, DWORD num, PDRIVEINFO driveInfo);


//强制卸载卷
BOOL DisMountVolum(char letter);

//解除锁定卷
BOOL UnlockVolume(char letter);

//锁定卷
BOOL LockVolum(char letter);

//输入盘符进行格式化
BOOL DiskFormat(char letter);

//输入盘符返回所在的物理磁盘号
BOOL GetPhysicalNum(char letter, DWORD * num);

//获取物理磁盘上的所有分区     -----弃用
DWORD GetPartitionLetterFromPhysicalDrive(DWORD phyDriveNumber, CHAR **letters);

//输入盘符返回所在的物理磁盘号     ------弃用
DWORD GetPhysicalDriveFromPartitionLetter(CHAR letter);


//获取物理磁盘上的所有分区
BOOL GetLetterFromPhysicalDrive(DWORD physicalDriveNumber, CHAR * letterList, DWORD * count);

//删除分区信息
DWORD DestroyDisk(DWORD physicalDriveNumber);

//判断是否有保留扇区
//根据0扇区是否直接是文件系统引导判断 
//文件系统引导扇区 第三个字节开始之后的八个字节用来描述文件系统类型
BOOL HaveReserveSectors(DWORD physicalDriveNumber);

#endif