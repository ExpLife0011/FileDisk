
// FileDiskDynamicTestDlg.h : ͷ�ļ�
//

#pragma once


// CFileDiskDynamicTestDlg �Ի���
class CFileDiskDynamicTestDlg : public CDialogEx
{
// ����
public:
	CFileDiskDynamicTestDlg(CWnd* pParent = NULL);	// ��׼���캯��

// �Ի�������
	enum { IDD = IDD_FILEDISKDYNAMICTEST_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV ֧��


// ʵ��
protected:
	HICON m_hIcon;

	// ���ɵ���Ϣӳ�亯��
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedButtonMakeudisk();
	afx_msg void OnBnClickedButtonSetAuthority();
	afx_msg void OnBnClickedButtonUmountDriveletter();
	afx_msg void OnBnClickedButtonMountDriveletter();
};
