#ifndef _FUNCTION_H_
#define _FUNCTION_H_

#include <ntddk.h>
#include <Ntddstor.h>

typedef unsigned char BYTE;
#ifndef FILE_DISK_POOL_TAG
#define FILE_DISK_POOL_TAG 'ksiD'
#endif // !FILE_DISK_POOL_TAG


NTSTATUS
GetDeviceBusType(
__in PDEVICE_OBJECT Device,
__in __out BYTE* pBusType
);

#endif // _FUNCTION_H_


