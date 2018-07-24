#pragma once
#ifndef _DISKOPTION_
#define _DISKOPTION_

#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#include "PartitionEntry.h"


// ��ȡ����������
BOOL GetAllDrive(char * letterList, DWORD * count);

//ͨ�� \\\\.\\X: ��ȡ�����Ƿ�Ϊ�ƶ�����  type����Ϊ7Ϊ�ƶ�Ӳ��
DWORD GetDriveTypeByBus(const CHAR *drive, WORD *type);


//��ȡ���������Ϣ   ����������̺�   \\\\.\\PHYSICALDRIVE0
// disksize   ���̴�С -------------|
// cylinders  ���� -----------------|
// TracksPerCylinder  ÿ����ŵ��� --|	DriveInfo
// SectorsPerTrack   ÿ�ŵ������� ---|
// BytePerSector    ÿ�����ֽ��� ----|
BOOL GetPhysicalDriveInfo(DWORD physicalNum, PDRIVEINFO DriveInfo);


//��ʼд����  ͨ��������̺�
//��Ҫ��������0��������MBR����������2047���������  -----����
BOOL WritePhysicalDrive1(int num); 


//��ʼд����  ͨ��������̺�
//��Ҫ��������0��������MBR����������2047��������� 
BOOL WritePhysicalDrive(char letter, DWORD num, PDRIVEINFO driveInfo);

//��ʼд����  ���̷���ֻд10M��С
BOOL WriteSpecialUDisk(char letter, DWORD num, PDRIVEINFO driveInfo);


//ǿ��ж�ؾ�
BOOL DisMountVolum(char letter);

//���������
BOOL UnlockVolume(char letter);

//������
BOOL LockVolum(char letter);

//�����̷����и�ʽ��
BOOL DiskFormat(char letter);

//�����̷��������ڵ�������̺�
BOOL GetPhysicalNum(char letter, DWORD * num);

//��ȡ��������ϵ����з���     -----����
DWORD GetPartitionLetterFromPhysicalDrive(DWORD phyDriveNumber, CHAR **letters);

//�����̷��������ڵ�������̺�     ------����
DWORD GetPhysicalDriveFromPartitionLetter(CHAR letter);


//��ȡ��������ϵ����з���
BOOL GetLetterFromPhysicalDrive(DWORD physicalDriveNumber, CHAR * letterList, DWORD * count);

//ɾ��������Ϣ
DWORD DestroyDisk(DWORD physicalDriveNumber);

//�ж��Ƿ��б�������
//����0�����Ƿ�ֱ�����ļ�ϵͳ�����ж� 
//�ļ�ϵͳ�������� �������ֽڿ�ʼ֮��İ˸��ֽ����������ļ�ϵͳ����
BOOL HaveReserveSectors(DWORD physicalDriveNumber);

#endif