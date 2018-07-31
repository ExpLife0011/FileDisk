
// FileDiskDynamicTestDlg.cpp : 实现文件
//

#include "stdafx.h"
#include "FileDiskDynamicTest.h"
#include "FileDiskDynamicTestDlg.h"
#include "afxdialogex.h"

#include "..\\FileDiskDynamic\\FileDiskDynamic.h"
#include "DiskOption.h"

#pragma comment(lib, "..\\Debug\\FileDisk.lib")

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


#define UDISKOFFSET			(10485760 + 1024 + 1048576)

// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// 对话框数据
	enum { IDD = IDD_ABOUTBOX };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(CAboutDlg::IDD)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CFileDiskDynamicTestDlg 对话框



CFileDiskDynamicTestDlg::CFileDiskDynamicTestDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(CFileDiskDynamicTestDlg::IDD, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CFileDiskDynamicTestDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CFileDiskDynamicTestDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_BUTTON_MAKEUDISK, &CFileDiskDynamicTestDlg::OnBnClickedButtonMakeudisk)
	ON_BN_CLICKED(IDC_BUTTON_SET_AUTHORITY, &CFileDiskDynamicTestDlg::OnBnClickedButtonSetAuthority)
	ON_BN_CLICKED(IDC_BUTTON_UMOUNT_DRIVELETTER, &CFileDiskDynamicTestDlg::OnBnClickedButtonUmountDriveletter)
	ON_BN_CLICKED(IDC_BUTTON_MOUNT_DRIVELETTER, &CFileDiskDynamicTestDlg::OnBnClickedButtonMountDriveletter)
END_MESSAGE_MAP()


// CFileDiskDynamicTestDlg 消息处理程序

BOOL CFileDiskDynamicTestDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO:  在此添加额外的初始化代码

	InitialCommunicationPort();


	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CFileDiskDynamicTestDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CFileDiskDynamicTestDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CFileDiskDynamicTestDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}



void CFileDiskDynamicTestDlg::OnBnClickedButtonMakeudisk()
{
	// TODO:  在此添加控件通知处理程序代码

	CString driveLetter;
	GetDlgItemText(IDC_EDIT_DRIVELETTER, driveLetter);

	char c_driverLetter[10];

	int len = WideCharToMultiByte(CP_ACP, 0, driveLetter.GetBuffer(), -1, NULL, 0, NULL, NULL);
	WideCharToMultiByte(CP_ACP, 0, driveLetter.GetBuffer(), -1, c_driverLetter, len, NULL, NULL);

	MakeDisk(c_driverLetter[0]);
}


void CFileDiskDynamicTestDlg::OnBnClickedButtonSetAuthority()
{
	// TODO:  在此添加控件通知处理程序代码

	DWORD authority = GetDlgItemInt(IDC_EDIT_AUTHORITY);

	SetUDiskAuthority(authority);
}


void CFileDiskDynamicTestDlg::OnBnClickedButtonUmountDriveletter()
{
	// TODO:  在此添加控件通知处理程序代码
	CString driveLetter;
	GetDlgItemText(IDC_EDIT_UMOUNT_DRIVELETTER, driveLetter);

	char c_driveLetter[10];
	 
	int len = WideCharToMultiByte(CP_ACP, 0, driveLetter.GetBuffer(), -1, NULL, 0, NULL, NULL);
	WideCharToMultiByte(CP_ACP, 0, driveLetter.GetBuffer(), -1, c_driveLetter, len, NULL, NULL);

	FileDiskUmount(c_driveLetter[0]);

}


void CFileDiskDynamicTestDlg::OnBnClickedButtonMountDriveletter()
{
	// TODO:  在此添加控件通知处理程序代码

	CString driveLetterStr;
	GetDlgItemText(IDC_EDIT_MOUNT_DRIVELETTER, driveLetterStr);

	char c_driveLetter[10];

	int len = WideCharToMultiByte(CP_ACP, 0, driveLetterStr.GetBuffer(), -1, NULL, 0, NULL, NULL);
	WideCharToMultiByte(CP_ACP, 0, driveLetterStr.GetBuffer(), -1, c_driveLetter, len, NULL, NULL);

	char driveLetter = c_driveLetter[0];

	POPEN_FILE_INFORMATION  OpenFileInformation;
	char FileName[MAX_PATH] = { 0 };
	DWORD PhyDriveNo = 0;
	DRIVEINFO DriveInfo = { 0 };
	GetPhysicalNum(driveLetter, &PhyDriveNo);

	//获取磁盘相关信息
	GetPhysicalDriveInfo(PhyDriveNo, &DriveInfo);

	sprintf(FileName, "\\??\\physicaldrive%d", PhyDriveNo);
	OpenFileInformation =
		(POPEN_FILE_INFORMATION)malloc(sizeof(OPEN_FILE_INFORMATION) + strlen(FileName) + 7);

	if (OpenFileInformation == NULL)
	{
		return ;
	}

	memset(
		OpenFileInformation,
		0,
		sizeof(OPEN_FILE_INFORMATION) + strlen(FileName) + 7
		);

	if (FileName[0] == '\\')
	{
		if (FileName[1] == '\\')
			// \\server\share\path\filedisk.img
		{
			strcpy(OpenFileInformation->FileName, "\\??\\UNC");
			strcat(OpenFileInformation->FileName, FileName + 1);
		}
		else
			// \Device\Harddisk0\Partition1\path\filedisk.img
		{
			strcpy(OpenFileInformation->FileName, FileName);
		}
	}
	else
		// c:\path\filedisk.img
	{
		strcpy(OpenFileInformation->FileName, "\\??\\");
		strcat(OpenFileInformation->FileName, FileName);
	}

	OpenFileInformation->FileNameLength =
		(USHORT)strlen(OpenFileInformation->FileName);

	OpenFileInformation->DriveLetter = driveLetter + 1;
	OpenFileInformation->PhysicalDrive = TRUE;
	OpenFileInformation->FileOffset.QuadPart = UDISKOFFSET;
	OpenFileInformation->ReadOnly = FALSE;
	//u盘的大小
	OpenFileInformation->FileSize.QuadPart = DriveInfo.DiskSize - UDISKOFFSET;

	DWORD DeviceNumber = GetAvailableDeviceNumber();
	if (DeviceNumber < 0)
	{
		return ;
	}

	FileDiskMount(DeviceNumber, OpenFileInformation, FALSE);		//挂载u盘
}
