#include "function.h"


NTSTATUS
GetDeviceBusType(
__in PDEVICE_OBJECT Device,
__in __out BYTE* pBusType
)
{
	PIRP Irp;
	KEVENT Event;
	NTSTATUS status;
	IO_STATUS_BLOCK Iosb;
	STORAGE_PROPERTY_QUERY PropQuery;
	PSTORAGE_DEVICE_DESCRIPTOR pDesc;
	PVOID QueryBuffer = NULL;
	ULONG QuerySize = 0x2000;

	__try
	{
		QueryBuffer = ExAllocatePoolWithTag(NonPagedPool, QuerySize, FILE_DISK_POOL_TAG);
		if (!QueryBuffer)
		{
			status = STATUS_INSUFFICIENT_RESOURCES;
			__leave;
		}

		memset(&PropQuery, 0, sizeof(PropQuery));
		memset(QueryBuffer, 0, QuerySize);
		PropQuery.PropertyId = StorageDeviceProperty;
		PropQuery.QueryType = PropertyStandardQuery;

		KeInitializeEvent(&Event, NotificationEvent, FALSE);
		//
		//A driver that calls IoBuildDeviceIoControlRequest must not call IoFreeIrp, 
		//because the I/O manager frees these synchronous IRPs after IoCompleteRequest has been called.
		//
		Irp = IoBuildDeviceIoControlRequest(
			IOCTL_STORAGE_QUERY_PROPERTY,
			Device,
			&PropQuery,
			sizeof(PropQuery),
			QueryBuffer,
			QuerySize,
			FALSE,
			&Event,
			&Iosb
			);

		if (!Irp)
		{
			status = STATUS_UNSUCCESSFUL;
			__leave;
		}

		status = IoCallDriver(Device, Irp);

		if (STATUS_PENDING == status)
		{
			KeWaitForSingleObject(
				&Event,
				Executive,
				KernelMode,
				FALSE,
				(PLARGE_INTEGER)NULL
				);

			status = Iosb.Status;
		}

		if (!NT_SUCCESS(status))
		{
			__leave;
		}

		if (!Iosb.Information)
		{
			status = STATUS_UNSUCCESSFUL;
			__leave;
		}

		pDesc = (PSTORAGE_DEVICE_DESCRIPTOR)QueryBuffer;

		if (pBusType)
			*pBusType = (BYTE)pDesc->BusType;
	}
	__finally
	{
		if (QueryBuffer)
			ExFreePoolWithTag(QueryBuffer, FILE_DISK_POOL_TAG);
	}

	return status;
}