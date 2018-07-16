// #ifndef _HOOKIRP_H_
// #define _HOOKIRP_H_
// 
// #include <ntddk.h>
// 
// #define HOOK_DRIVER_NAME     L"\\Driver\\Disk" 
// 
// #ifdef __cplusplus
// extern "C"
// {
// #endif
// 
// 
// typedef struct _DVCLOCK_DEVICE_INFO_EX{
// 
// 	// -- ����
// 	struct _DVCLOCK_DEVICE_INFO_EX *Next;
// 
// 	// -- �豸������Ϣ
// 	PVOID					        DeviceObject;           //�豸����(PDEVICE_OBJECT)
// 	PVOID                           DeviceVpb;              //
// 	BYTE                            DeviceBusType;          //�豸��������
// 
// 	BOOLEAN                         PasswordCheckd;         //�����Ѿ���֤
// 	BOOLEAN                         WirteProtect;           //�Ƿ�д����
// 
// 	BOOLEAN                         EnableUse;              //�Ƿ񱻽���
// 	ULONG                           RegType;                //ע������ EMS_REG_TYPE_XXXX
// 	ULONG                           UseAuthority;           //ʹ��Ȩ�� EMS_AUTHORITY_XXX
// 	BYTE                            DiskSN[DISK_SN_LENGTH]; //�������к� ------------------------------Ϊô��ΪCHAR����
// 
// 	BYTE                            ExceptionUDisk;         //�����豸
// 
// 	// -- �����豸����
// 	BYTE                            DiskConIndex[CONFILE_INDEX_LEN]; //CConIndex
// 	BYTE                            TempConIndex[CONFILE_INDEX_LEN]; //�滻1AD��������
// 	PVOID                           DiskConFile;            //(CConFile *) 
// 	PVOID                           Disk0Sector;            //����0��������
// 	PVOID                           Disk0SectorSrc;         //����0����ԭʼ����/*0��������*/
// 
// 	BYTE                            ResetDiskCon;           //�Ƿ����¶�ȡ
// 	BYTE                            EncDiskFlags;			//Modify shizhiq ����U�̱�� ����� ɾ���� ������
// 	BYTE							NewEncFlags;
// 	// -- ����
// 	PVOID                           Expand;                 //��չ
// 	DWORD                           Reserved;               //����
// 	LARGE_INTEGER  ReadTime;
// 	LARGE_INTEGER  WriteTime;
// 	LARGE_INTEGER FirstWirteTime; //��¼���̶�д��ֵ 500����
// 	struct _DVCLOCK_DEVICE_INFO_EX * pListNode;
// 	BOOLEAN blTimeOut; //�Ƿ�ʱ�ӹҾ��ʱ��ִ��д�������ƣ�3����д����ʱ�䡣������ִ�ж�Ӧ�Ĳ���
// 	BOOLEAN blMount; //�Ƿ�mount��
// }DVCLOCK_DEVICE_INFO_EX, *PDVCLOCK_DEVICE_INFO_EX;
// 
// //
// // -- HOOK DISK.SYS �ص�����
// //
// BOOLEAN
// 	HookIRP_Install(VOID);
// 
// //
// // -- HOOK DISK.SYS �ص�����
// //
// BOOLEAN
// 	HookIRP_Uninstall(VOID);
// 
// NTSTATUS
// HookIrp_DispatchPnpDisk(
// IN PDEVICE_OBJECT DeviceObject,
// IN PIRP Irp
// );
// 
// 
// NTSTATUS
// HookIrp_CallPnpDisk(
// IN PDEVICE_OBJECT DeviceObject,
// IN PIRP Irp
// );
// 
// #ifdef __cplusplus
// }
// #endif
// 
// #endif // !_HOOKIRP_H_
