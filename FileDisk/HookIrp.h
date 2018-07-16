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
// 	// -- 链表
// 	struct _DVCLOCK_DEVICE_INFO_EX *Next;
// 
// 	// -- 设备对象信息
// 	PVOID					        DeviceObject;           //设备对象(PDEVICE_OBJECT)
// 	PVOID                           DeviceVpb;              //
// 	BYTE                            DeviceBusType;          //设备总线类型
// 
// 	BOOLEAN                         PasswordCheckd;         //密码已经验证
// 	BOOLEAN                         WirteProtect;           //是否写保护
// 
// 	BOOLEAN                         EnableUse;              //是否被禁用
// 	ULONG                           RegType;                //注册类型 EMS_REG_TYPE_XXXX
// 	ULONG                           UseAuthority;           //使用权限 EMS_AUTHORITY_XXX
// 	BYTE                            DiskSN[DISK_SN_LENGTH]; //磁盘序列号 ------------------------------为么不为CHAR类型
// 
// 	BYTE                            ExceptionUDisk;         //例外设备
// 
// 	// -- 磁盘设备对象
// 	BYTE                            DiskConIndex[CONFILE_INDEX_LEN]; //CConIndex
// 	BYTE                            TempConIndex[CONFILE_INDEX_LEN]; //替换1AD区域数据
// 	PVOID                           DiskConFile;            //(CConFile *) 
// 	PVOID                           Disk0Sector;            //磁盘0扇区内容
// 	PVOID                           Disk0SectorSrc;         //磁盘0扇区原始内容/*0扇区解密*/
// 
// 	BYTE                            ResetDiskCon;           //是否重新读取
// 	BYTE                            EncDiskFlags;			//Modify shizhiq 加密U盘标记 审计中 删除中 可用中
// 	BYTE							NewEncFlags;
// 	// -- 保留
// 	PVOID                           Expand;                 //扩展
// 	DWORD                           Reserved;               //保留
// 	LARGE_INTEGER  ReadTime;
// 	LARGE_INTEGER  WriteTime;
// 	LARGE_INTEGER FirstWirteTime; //记录磁盘读写差值 500毫秒
// 	struct _DVCLOCK_DEVICE_INFO_EX * pListNode;
// 	BOOLEAN blTimeOut; //是否超时从挂卷的时候执行写操作控制，3分钟写操作时间。超过就执行对应的策略
// 	BOOLEAN blMount; //是否mount上
// }DVCLOCK_DEVICE_INFO_EX, *PDVCLOCK_DEVICE_INFO_EX;
// 
// //
// // -- HOOK DISK.SYS 回调例程
// //
// BOOLEAN
// 	HookIRP_Install(VOID);
// 
// //
// // -- HOOK DISK.SYS 回调例程
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
