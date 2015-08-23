
/**************************************************************************************
			The Luzj's Zte Project
			//////////////////////
			Copyleft ? 2009 Luzj
		Author:Luzj		QQ:86829232
		http://blog.csdn.net/luzjqq
		Email: luzjcn@gmail.com
	///////////////////////////////////
����Luzj's Zte��֤�˵�������

1������������漰��������֤�Ĺ��ܵ�ʵ�־���ͨ���ںз�����������δͨ���κβ�����������á�

2������������о�ѧϰ֮�ã�����ʹ�ñ���������˹�˾��ҵ���档

3����������������κ���ҵ�ͷǷ���;�����������Ը���

4��������ڷ���ǰ��ͨ��һ����Ӧ�ò��ԣ�������֤�κ�����¶Ի����޺���
����δ֪��ʹ�û����򲻵���ʹ�öԼ������ɵ��𺦣�������ʹ����ȫ���е���

5.�������Ȩû�У���ӡ����������Э���Ľ�����Ʒ��

6.���������Դ����������Ҫ�޸ı����Դ���Խ��ж��η�����Ҳ���������Դ���롣

�����κβ�����������������ľ��ף����뱾���޹أ��粻ͬ��������벻Ҫʹ�ø������лл������
**************************************************************************************/


// Luzj_ZTE.cpp : Defines the class behaviors for the application.
//

#include "stdafx.h"
#include "Luzj_ZTE.h"
#include "Luzj_ZTEDlg.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/////////////////////////////////////////////////////////////////////////////
// CLuzj_ZTEApp

BEGIN_MESSAGE_MAP(CLuzj_ZTEApp, CWinApp)
	//{{AFX_MSG_MAP(CLuzj_ZTEApp)
		// NOTE - the ClassWizard will add and remove mapping macros here.
		//    DO NOT EDIT what you see in these blocks of generated code!
	//}}AFX_MSG
	ON_COMMAND(ID_HELP, CWinApp::OnHelp)
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////
// CLuzj_ZTEApp construction

CLuzj_ZTEApp::CLuzj_ZTEApp()
{
	// TODO: add construction code here,
	// Place all significant initialization in InitInstance
}

/////////////////////////////////////////////////////////////////////////////
// The one and only CLuzj_ZTEApp object

CLuzj_ZTEApp theApp;

/////////////////////////////////////////////////////////////////////////////
// CLuzj_ZTEApp initialization

BOOL CLuzj_ZTEApp::InitInstance()
{
	AfxEnableControlContainer();

	// Standard initialization
	// If you are not using these features and wish to reduce the size
	//  of your final executable, you should remove from the following
	//  the specific initialization routines you do not need.

#ifdef _AFXDLL
	Enable3dControls();			// Call this when using MFC in a shared DLL
#else
	Enable3dControlsStatic();	// Call this when linking to MFC statically
#endif


	HANDLE g_mutex	=  CreateMutex(NULL,FALSE,"LuzjZte");
	HWND findHwnd;
	if ( GetLastError()== ERROR_ALREADY_EXISTS )
	{
		//MessageBox(NULL,"���Ѿ�������һ����֤��!","����",MB_OK |MB_ICONERROR);
		if ((findHwnd=FindWindow(NULL,STR_AppName))!=NULL)
		{
			//MessageBox(NULL,"�ҵ��Ǹ���֤����","����",MB_OK |MB_ICONERROR);
			ShowWindow(findHwnd,SW_SHOW);
			MessageBox(findHwnd,"ֻ��������һ����֤��!","����",MB_OK |MB_ICONERROR);
		}
		else
		{
			MessageBox(NULL,"ֻ��������һ����֤��!","����",MB_OK |MB_ICONERROR);
		}
		return 0;
	}

	CLuzj_ZTEDlg dlg;
	m_pMainWnd = &dlg;
	int nResponse = dlg.DoModal();
	if (nResponse == IDOK)
	{
		// TODO: Place code here to handle when the dialog is
		//  dismissed with OK
	}
	else if (nResponse == IDCANCEL)
	{
		// TODO: Place code here to handle when the dialog is
		//  dismissed with Cancel
	}

	// Since the dialog has been closed, return FALSE so that we exit the
	//  application, rather than start the application's message pump.
	return FALSE;
}
