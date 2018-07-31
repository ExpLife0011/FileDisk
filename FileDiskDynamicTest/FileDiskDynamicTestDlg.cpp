
// FileDiskDynamicTestDlg.cpp : ʵ���ļ�
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

// ����Ӧ�ó��򡰹��ڡ��˵���� CAboutDlg �Ի���

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// �Ի�������
	enum { IDD = IDD_ABOUTBOX };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV ֧��

// ʵ��
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


// CFileDiskDynamicTestDlg �Ի���



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


// CFileDiskDynamicTestDlg ��Ϣ�������

BOOL CFileDiskDynamicTestDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// ��������...���˵�����ӵ�ϵͳ�˵��С�

	// IDM_ABOUTBOX ������ϵͳ���Χ�ڡ�
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

	// ���ô˶Ի����ͼ�ꡣ  ��Ӧ�ó��������ڲ��ǶԻ���ʱ����ܽ��Զ�
	//  ִ�д˲���
	SetIcon(m_hIcon, TRUE);			// ���ô�ͼ��
	SetIcon(m_hIcon, FALSE);		// ����Сͼ��

	// TODO:  �ڴ���Ӷ���ĳ�ʼ������

	InitialCommunicationPort();


	return TRUE;  // ���ǽ��������õ��ؼ������򷵻� TRUE
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

// �����Ի��������С����ť������Ҫ����Ĵ���
//  �����Ƹ�ͼ�ꡣ  ����ʹ���ĵ�/��ͼģ�͵� MFC Ӧ�ó���
//  �⽫�ɿ���Զ���ɡ�

void CFileDiskDynamicTestDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // ���ڻ��Ƶ��豸������

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// ʹͼ���ڹ����������о���
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// ����ͼ��
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//���û��϶���С������ʱϵͳ���ô˺���ȡ�ù��
//��ʾ��
HCURSOR CFileDiskDynamicTestDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}



void CFileDiskDynamicTestDlg::OnBnClickedButtonMakeudisk()
{
	// TODO:  �ڴ���ӿؼ�֪ͨ����������

	CString driveLetter;
	GetDlgItemText(IDC_EDIT_DRIVELETTER, driveLetter);

	char c_driverLetter[10];

	int len = WideCharToMultiByte(CP_ACP, 0, driveLetter.GetBuffer(), -1, NULL, 0, NULL, NULL);
	WideCharToMultiByte(CP_ACP, 0, driveLetter.GetBuffer(), -1, c_driverLetter, len, NULL, NULL);

	MakeDisk(c_driverLetter[0]);
}


void CFileDiskDynamicTestDlg::OnBnClickedButtonSetAuthority()
{
	// TODO:  �ڴ���ӿؼ�֪ͨ����������

	DWORD authority = GetDlgItemInt(IDC_EDIT_AUTHORITY);

	SetUDiskAuthority(authority);
}


void CFileDiskDynamicTestDlg::OnBnClickedButtonUmountDriveletter()
{
	// TODO:  �ڴ���ӿؼ�֪ͨ����������
	CString driveLetter;
	GetDlgItemText(IDC_EDIT_UMOUNT_DRIVELETTER, driveLetter);

	char c_driveLetter[10];
	 
	int len = WideCharToMultiByte(CP_ACP, 0, driveLetter.GetBuffer(), -1, NULL, 0, NULL, NULL);
	WideCharToMultiByte(CP_ACP, 0, driveLetter.GetBuffer(), -1, c_driveLetter, len, NULL, NULL);

	FileDiskUmount(c_driveLetter[0]);

}


void CFileDiskDynamicTestDlg::OnBnClickedButtonMountDriveletter()
{
	// TODO:  �ڴ���ӿؼ�֪ͨ����������

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

	//��ȡ���������Ϣ
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
	//u�̵Ĵ�С
	OpenFileInformation->FileSize.QuadPart = DriveInfo.DiskSize - UDISKOFFSET;

	DWORD DeviceNumber = GetAvailableDeviceNumber();
	if (DeviceNumber < 0)
	{
		return ;
	}

	FileDiskMount(DeviceNumber, OpenFileInformation, FALSE);		//����u��
}
