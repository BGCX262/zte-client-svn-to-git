
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



// Luzj_ZTEDlg.cpp : implementation file
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
// CLuzj_ZTEDlg dialog
CLuzj_ZTEDlg::CLuzj_ZTEDlg(CWnd* pParent /*=NULL*/)
	: CDialog(CLuzj_ZTEDlg::IDD, pParent)
{
	//{{AFX_DATA_INIT(CLuzj_ZTEDlg)
	m_pass = _T("");
	m_user = _T("");
	//}}AFX_DATA_INIT
	// Note that LoadIcon does not require a subsequent DestroyIcon in Win32
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);

	//��֤״̬Ϊ δ��֤
	m_bAuth=FALSE;
}

void CLuzj_ZTEDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	//{{AFX_DATA_MAP(CLuzj_ZTEDlg)
	DDX_Control(pDX, IDC_USERNAME, m_ccb_username);
	DDX_CBString(pDX, IDC_USERNAME, m_user);
	DDX_Text(pDX, IDC_PWD, m_pass);
	DDX_Control(pDX, IDC_LIST_LOG, m_lcLog);
	DDX_Control(pDX, IDC_TOPPIC, m_pic);
	DDX_Control(pDX, IDC_NETCARD, m_ccbNetCard);
	//}}AFX_DATA_MAP
}

BEGIN_MESSAGE_MAP(CLuzj_ZTEDlg, CDialog)
	//{{AFX_MSG_MAP(CLuzj_ZTEDlg)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_START, OnStart)
	ON_BN_CLICKED(IDC_LOGOFF, OnLogoff)
	ON_BN_CLICKED(IDC_TEST, OnTest)
	ON_BN_CLICKED(IDC_EXIT, OnExit)
	ON_BN_CLICKED(MENU_SHOW, OnTrayShow)
	ON_BN_CLICKED(MENU_EXIT, OnExit)
	ON_MESSAGE(WM_USER_TRAY_NOTIFICATION,OnTrayNotification)
	ON_WM_TIMER()
	ON_BN_CLICKED(IDC_SETTING, OnSetting)
	ON_BN_CLICKED(IDC_LOGSHOW, OnLogshow)
	ON_CBN_SELCHANGE(IDC_USERNAME, OnSelchangeUsername)
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()


BOOL CLuzj_ZTEDlg::OnInitDialog()
{
	CDialog::OnInitDialog();

	SetIcon(m_hIcon, TRUE);			// Set big icon
	SetIcon(m_hIcon, FALSE);		// Set small icon
	
	SetWindowText(STR_AppName);

	//��������ͼ��
	m_tray.Create(this, WM_USER_TRAY_NOTIFICATION,STR_AppName, m_hIcon, 0);

	//�޸��б�ؼ�
	m_lcLog.SetExtendedStyle(LVS_EX_FULLROWSELECT|LVS_EX_FLATSB|LVS_EX_GRIDLINES );
	m_lcLog.InsertColumn(1,"ʱ��",LVCFMT_CENTER,80);
	m_lcLog.InsertColumn(2,"�¼�",LVCFMT_CENTER,260);


	GetWindowRect(&m_rc);
	m_rc.top=m_rc.bottom-5;    //����״̬���ľ�������
	m_StatusBar.Create(WS_CHILD |WS_VISIBLE|CBRS_BOTTOM,m_rc,this,20000);  
	int nParts[2]= {100,-1};      //�ָ�ߴ�
	m_StatusBar.SetParts(2, nParts);
	m_StatusBar.SetText("  00ʱ00��00��",0,0);
	m_StatusBar.SetText("        ״̬:  δ��֤",1,0);

	//����״̬������ʾ
	SetTimer(1,1000,NULL);
	//��ʼ��ʱ���Ƚ���־������
	OnLogshow();

	//////////////////////////////////////////////////////////////////////////
	char szTemp[MAX_STRING];
	int i=0,k=0;
	CString str;

	//��ȡ���õ��ļ����ö�����ȥ
	Config.LoadConfig();

	CheckDlgButton(IDC_REMEMBER,Config.m_bRememberPWD?BST_CHECKED:BST_UNCHECKED);
	//////////////////////////////////////////////////////////////////////////
	//�����˺���Ϣ
	userInfo user;
	i=Config.m_UserInfo.GetCount();

	for (k=0;k<i;k++)
	{
		Config.m_UserInfo.Lookup(k,user);
		m_ccb_username.AddString(user.user);
	}
	m_ccb_username.SetCurSel(0);
	for (k=0;k<i;k++)
	{
		Config.m_UserInfo.Lookup(k,user);
		if (user.user==Config.m_csLastUser)
		{
			m_ccb_username.SetCurSel(k);
			GetDlgItem(IDC_PWD)->SetWindowText(user.pass);
			break;
		}
	}

	//////////////////////////////////////////////////////////////////////////

	//////////////////////////////////////////////////////////////////////////
	//����������Ϣ
	char m_errorBuffer[ PCAP_ERRBUF_SIZE ];		//������Ϣ������
	pcap_if_t		* allAdapters;				//�������б�
	if(pcap_findalldevs(&allAdapters, m_errorBuffer) == -1 || allAdapters == NULL)
	{
		MessageBox("��ȡ������Ϣʧ�ܣ���ȷ���㰲װ��WinPcap!","����",MB_ICONERROR|MB_OK);
		pcap_freealldevs(allAdapters);
		CDialog::OnCancel();
	}

	pcap_if_t* adapter;//��ʱ���������
    for(adapter = allAdapters; adapter != NULL; adapter = adapter->next)
    {
		m_ccbNetCard.AddString(adapter->description);
    }
	pcap_freealldevs(allAdapters);


	m_ccbNetCard.SetCurSel(0);
	for (i=0;i<m_ccbNetCard.GetCount();i++)
	{
		m_ccbNetCard.GetLBText(i,szTemp);
		if (strcmp(szTemp,Config.m_csNetCard)==0)
		{
			m_ccbNetCard.SetCurSel(i);
			break;
		}
	}
	
	this->AddLog("�����������");
	//////////////////////////////////////////////////////////////////////////



	//ʹ�ÿ�ʼ��ť��Ч�����Ͽ���ť��Ч
	this->ChgBtn(TRUE);  

	//������򶥲�ͼƬ�Ĵ�С
	RECT rc={0};
	GetDlgItem(IDC_TOPPIC)->GetWindowRect(&rc);
	m_pic.x=rc.right-rc.left;
	m_pic.y=rc.bottom-rc.top;

	if (Config.m_bAutologon == TRUE)
	{
		ShowWindow(SW_HIDE);
		this->OnStart();
	}
	SetProcessWorkingSetSize(GetCurrentProcess(),-1,-1);
	return TRUE;  // return TRUE  unless you set the focus to a control
}

void CLuzj_ZTEDlg::ChgBtn(bool bStart,char * szMsg)
{
	if (bStart)
	{
		GetDlgItem(IDC_LOGOFF)->EnableWindow(FALSE);
		GetDlgItem(IDC_START)->EnableWindow(TRUE);
	} 
	else
	{
		GetDlgItem(IDC_LOGOFF)->EnableWindow(TRUE);
		GetDlgItem(IDC_START)->EnableWindow(FALSE);
	}
	if (szMsg!=NULL)
	{
		SetBubble("��ʾ",szMsg);
		MessageBox(szMsg,"����",MB_ICONERROR|MB_OK);
	}
}


void CLuzj_ZTEDlg::AddLog(CString addStr)
{
	time_t t=time(NULL);
	char szTime[MAX_STRING];
	strftime(szTime,MAX_STRING,"%Hʱ%M��%S��",localtime(&t));	
	if (m_lcLog.GetItemCount()>80)
	{
		m_lcLog.DeleteAllItems();
	}
	m_lcLog.InsertItem(0,szTime);
	m_lcLog.SetItemText(0,1,addStr);
}

void CLuzj_ZTEDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == SC_MINIMIZE || (nID & 0xFFF0) == SC_CLOSE)
	{
		ShowWindow(SW_HIDE);
		SetProcessWorkingSetSize(GetCurrentProcess(),-1,-1);
		SetBubble("��ʾ",STR_AppName" ���ں�̨�����š���",1);
	}
	else
	{
		CDialog::OnSysCommand(nID, lParam);
	}
}
void CLuzj_ZTEDlg::SetBubble(char * title,char * content,int timeout)
{
	if (Config.m_bShowBubble==TRUE)
	{
		m_tray.SetBubble(title,content,timeout);
	}
}

void CLuzj_ZTEDlg::OnTrayShow()
{   
	if (IsWindowVisible())
	{
		ShowWindow(SW_HIDE);
		SetProcessWorkingSetSize(GetCurrentProcess(),-1,-1);
	} 
	else
	{
		ShowWindow(SW_SHOW);
	}
}


LONG CLuzj_ZTEDlg::OnTrayNotification(WPARAM wparam, LPARAM lparam)
{   
	CMenu	m_menu;
	CPoint	m_point;
	switch (lparam)
	{
	case WM_RBUTTONDOWN:
		m_menu.CreatePopupMenu();
		if (IsWindowVisible())
		{
			m_menu.AppendMenu(MF_ENABLED, MENU_SHOW,_T("���ش���"));
		} 
		else
		{
			m_menu.AppendMenu(MF_ENABLED, MENU_SHOW,_T("��ʾ����"));
		}
		m_menu.AppendMenu(MF_ENABLED, MF_SEPARATOR);
		m_menu.AppendMenu(MF_ENABLED, MENU_EXIT,_T("�� ��"));
		GetCursorPos(&m_point);
		m_menu.TrackPopupMenu(TPM_LEFTALIGN,m_point.x,m_point.y,this);
		break;
	case WM_LBUTTONDOWN:
		if (IsWindowVisible())
		{
			ShowWindow(SW_HIDE);
			SetProcessWorkingSetSize(GetCurrentProcess(),-1,-1);
		}
		else
		{
			ShowWindow(SW_SHOW);
			BringWindowToTop();
		}	
		break;
	}
	return 0;
}

void CLuzj_ZTEDlg::OnPaint() 
{
	if (IsIconic())
	{
		CPaintDC dc(this); // device context for painting

		SendMessage(WM_ICONERASEBKGND, (WPARAM) dc.GetSafeHdc(), 0);

		// Center icon in client rectangle
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// Draw the icon
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialog::OnPaint();
	}
}

// The system calls this to obtain the cursor to display while the user drags
//  the minimized window.
HCURSOR CLuzj_ZTEDlg::OnQueryDragIcon()
{
	return (HCURSOR) m_hIcon;
}

void CLuzj_ZTEDlg::OnStart() 
{
	//////////////////////////////////////////////////////////////////////////
	//		�ȴ�����ò���
	CString str,strUser,strPass,strTemp;

	//ȡ���û�������
	this->getUserInfo();
	if (m_usernameLen<1 || m_passwordLen<1)
	{
		this->ChgBtn(TRUE,"�û�����������̫��!");
		return;	
	}
	this->ChgBtn(FALSE);

	GetDlgItem(IDC_NETCARD)->GetWindowText(strTemp);
	Config.m_csNetCard=strTemp;

	GetDlgItem(IDC_USERNAME)->GetWindowText(strUser);
	if (IsDlgButtonChecked(IDC_REMEMBER))
	{
		GetDlgItem(IDC_PWD)->GetWindowText(strPass);
		Config.m_bRememberPWD=TRUE;
	}
	else
	{
		strPass="";
		Config.m_bRememberPWD=FALSE;
	}

	Config.m_csLastUser=strUser;
	userInfo user;
	int i=0,k=0;
	i=Config.m_UserInfo.GetCount();
	for (k=0;k<i;k++)
	{
		Config.m_UserInfo.Lookup(k,user);
		if (user.user==strUser)
		{
			break;
		}
	}
	user.user=strUser;
	user.pass=strPass;
	Config.m_UserInfo.SetAt(k,user);


	Config.SvaeConfig();
	//////////////////////////////////////////////////////////////////////////

	SetBubble("��ʾ",STR_AppName" ��ʼ������֤����");

	DWORD dwPID;
	m_AuthThread=CreateThread(NULL,0,CLuzj_ZTEDlg::StartAuth,this,0,&dwPID);
}


DWORD WINAPI CLuzj_ZTEDlg::StartAuth(LPVOID pParam)
{
	CLuzj_ZTEDlg* Dlg=(CLuzj_ZTEDlg*)pParam;
	int			retcode;
	const int	DefaultTimeout=1000;
	
	/////////////////////////////////////////////////////////////////////////
	//Ѱ����ѡ��������MAC
	IP_ADAPTER_INFO AdapterInfo[16];
	DWORD dwBufLen = sizeof(AdapterInfo);
	DWORD dwStatus = GetAdaptersInfo(AdapterInfo,&dwBufLen);
 	PIP_ADAPTER_INFO pAdapterInfo = AdapterInfo;

	pcap_if_t* adapter;							//��ʱ���������
	pcap_if_t* allAdapters;						//�������б�
	char m_errorBuffer[ PCAP_ERRBUF_SIZE ];		//������Ϣ������
	if(pcap_findalldevs(&allAdapters, m_errorBuffer) == -1 || allAdapters == NULL)
	{
		Dlg->ChgBtn(TRUE,"��ȡ������Ϣʧ�ܣ���ȷ���㰲װ��WinPcap!");
		pcap_freealldevs(allAdapters);
		return 0;
	}
    for(adapter = allAdapters; adapter != NULL; adapter= adapter->next)
    {
		if (strcmp(adapter->description,Config.m_csNetCard)==0)
		{
			break;
		}
    }

	do{
		if (strstr(adapter->name,pAdapterInfo->AdapterName)>0)
		{
			Dlg->m_MacAdd[0]=pAdapterInfo->Address[0];
			Dlg->m_MacAdd[1]=pAdapterInfo->Address[1];
			Dlg->m_MacAdd[2]=pAdapterInfo->Address[2];
			Dlg->m_MacAdd[3]=pAdapterInfo->Address[3];
			Dlg->m_MacAdd[4]=pAdapterInfo->Address[4];
			Dlg->m_MacAdd[5]=pAdapterInfo->Address[5];
			break;
		}
	}while(pAdapterInfo = pAdapterInfo->Next);


	if (!pAdapterInfo)
	{
		Dlg->ChgBtn(TRUE,"����Ĵ��󣬾�Ȼû���ҵ�������MAC!");
		return 0;
	}
	if (pAdapterInfo->DhcpEnabled!=1)//�������Ƿ������˶�̬��������Э�飨DHCP��
	{
		Dlg->ChgBtn(TRUE,"����ȥ �������--����--���� ���棬��DHCP��������!");
		return 0;
	}

	//////////////////////////////////////////////////////////////////////////
	// ��ָ��������
    if((Dlg->m_adapterHandle=pcap_open_live(adapter->name,65536,1,DefaultTimeout,m_errorBuffer)) == NULL)
    {
		Dlg->ChgBtn(TRUE,"�޷�������!");
		pcap_freealldevs(allAdapters);
		return 0;
    }
	pcap_freealldevs(allAdapters);


	Dlg->AddLog("����ָ������������");



	char	FilterStr[100];		//�������ַ���
	struct bpf_program	mfcode;	
	const u_char		*captured;
	struct pcap_pkthdr	*header;

	sprintf(FilterStr, "(ether proto 0x888e) and (ether dst host %02x:%02x:%02x:%02x:%02x:%02x)",
			Dlg->m_MacAdd[0],Dlg->m_MacAdd[1],Dlg->m_MacAdd[2],Dlg->m_MacAdd[3],Dlg->m_MacAdd[4],Dlg->m_MacAdd[5]);

    if(pcap_compile(Dlg->m_adapterHandle, &mfcode, FilterStr, 1, 0xff)==-1
		||pcap_setfilter(Dlg->m_adapterHandle, &mfcode)==-1)
    {
		Dlg->ChgBtn(TRUE,"���˰����ô���!");
		return 0;
    }
	Dlg->AddLog("��������֤�����˼���");


	CPacket packet;
	time_t t1,t2;

	//////////////////////////////////////////////////////////////////////////
	///��ʼ��֤��
    if(!packet.send_packet_start(Dlg->m_adapterHandle,Dlg->m_MacAdd))
    {
        Dlg->ChgBtn(TRUE,"EAPOL-Start������ʧ��!");
		Dlg->AddLog("EAPOL-Start������ʧ��!");
		return 0;
    }
	Dlg->AddLog("���� EAPOL-Start ����������֤");
	//////////////////////////////////////////////////////////////////////////
	//���ջ�Ӧ��
	t1=time(NULL);
	retcode=pcap_next_ex(Dlg->m_adapterHandle, &header, &captured);
	t2=time(NULL);
	while(retcode!=1 && t2-t1<Config.m_iTimeout)
	{
		Sleep(1000);
		retcode=pcap_next_ex(Dlg->m_adapterHandle, &header, &captured);
		t2=time(NULL);
	}
	if (retcode!=1)
	{
		Dlg->ChgBtn(TRUE,"����EAPOL-Start��,��������Ӧ��ʱ!");
		Dlg->AddLog("����EAPOL-Start��,��������Ӧ��ʱ!");
		return 0;
	}
	//////////////////////////////////////////////////////////////////////////
	//����EAP-Identity��
	if(!packet.send_packet_response_Identity(Dlg->m_adapterHandle,captured,Dlg->m_MacAdd,Dlg->m_username,Dlg->m_usernameLen))
	{
		Dlg->ChgBtn(TRUE,"EAP-Identity������ʧ��!");
		return 0;
	}
	Dlg->AddLog("���� EAP-Identity �����ύ�˺�");
	//////////////////////////////////////////////////////////////////////////
	//���ջ�Ӧ��
	t1=time(NULL);
	retcode=pcap_next_ex(Dlg->m_adapterHandle, &header, &captured);
	t2=time(NULL);
	while(retcode!=1 && t2-t1<Config.m_iTimeout)
	{
		Sleep(1000);
		retcode=pcap_next_ex(Dlg->m_adapterHandle, &header, &captured);
		t2=time(NULL);
	}
	if (retcode!=1)
	{
		Dlg->ChgBtn(TRUE,"����EAP-Identity��,��������Ӧ��ʱ!");
		Dlg->AddLog("����EAP-Identity��,��������Ӧ��ʱ!");
		return 0;
	}
	//////////////////////////////////////////////////////////////////////////
	//����MD5��ս��
    if(!packet.send_packet_response_MD5(Dlg->m_adapterHandle,captured,Dlg->m_MacAdd,
										Dlg->m_username,Dlg->m_usernameLen,Dlg->m_password,Dlg->m_passwordLen))
    {
        Dlg->ChgBtn(TRUE,"MD5-Challenge������ʧ��!");
		return 0;
    }
	Dlg->AddLog("���� MD5-Challenge �����ύ����");
	//////////////////////////////////////////////////////////////////////////
	//���ջ�Ӧ��
	t1=time(NULL);
	retcode=pcap_next_ex(Dlg->m_adapterHandle, &header, &captured);
	t2=time(NULL);
	while(retcode!=1 && t2-t1<Config.m_iTimeout)
	{
		Sleep(1000);
		retcode=pcap_next_ex(Dlg->m_adapterHandle, &header, &captured);
		t2=time(NULL);
	}
	if (retcode!=1)
	{
		Dlg->ChgBtn(TRUE,"���� MD5-Challenge ��,��������Ӧ��ʱ!");
		Dlg->AddLog("���� MD5-Challenge ��,��������Ӧ��ʱ!");
		return 0;
	}
	if (captured[18]==0x03)
	{
		Dlg->AddLog("��������֤ͨ��");
	} 
	else
	{
		Dlg->ChgBtn(TRUE,"��������֤ʧ��,�������������!");
		Dlg->AddLog("��������֤ʧ��,�������������!");
		return 0;
	}
	//////////////////////////////////////////////////////////////////////////

	Dlg->ShowWindow(SW_HIDE);

	SHELLEXECUTEINFO ShExecInfo = {0};
	TCHAR tempBuffer[MAX_STRING];
	CString strSystemDirectory;
	GetSystemDirectory( tempBuffer, MAX_STRING);
	strSystemDirectory.Format(_T("%s\\ipconfig.exe"),tempBuffer);
	ShExecInfo.cbSize	= sizeof(SHELLEXECUTEINFO);
	ShExecInfo.fMask		= SEE_MASK_NOCLOSEPROCESS;
	ShExecInfo.lpFile		= strSystemDirectory;		
	ShExecInfo.lpParameters = _T("/renew");	
	ShExecInfo.nShow	= SW_HIDE;
	ShellExecuteEx(&ShExecInfo);
	
	int iRnt =WaitForSingleObject(ShExecInfo.hProcess,Config.m_iTimeout*1000);
	if (iRnt == WAIT_TIMEOUT) 
	{
		Dlg->SetBubble("��ʾ","  ��ȡIP��ʱ,�ж���֤!");
		return 0;
	}
	else if (iRnt == WAIT_FAILED)
	{
		Dlg->SetBubble("��ʾ","  ��ȡIPʧ��,�ж���֤!");
		return 0;
	}
	else
	{
		Dlg->SetBubble("��ʾ","  ��֤�ɹ�!");
	}

	Dlg->m_bAuth=TRUE;
	Dlg->m_startTime =time(NULL);
	SetProcessWorkingSetSize(GetCurrentProcess(),-1,-1);
	
	int iTimeOut=Config.m_iTimeout*2;
	while (Dlg->m_bAuth)
	{
		t1=time(NULL);
		retcode=pcap_next_ex(Dlg->m_adapterHandle, &header, &captured);
		t2=time(NULL);
		while(Dlg->m_bAuth && (t2-t1)<iTimeOut
			&& (captured[15]!=0x03 && captured[18]!=0x01 || retcode!=1))
		{
			Sleep(200);
			retcode=pcap_next_ex(Dlg->m_adapterHandle, &header, &captured);
			t2=time(NULL);
		}
		if (t2-t1>=iTimeOut)
		{
			Dlg->ChgBtn(TRUE,"����EAPOL-Key����ʱ,���������Ѿ��ж�!");
			Dlg->AddLog("����EAPOL-Key����ʱ,���������Ѿ��ж�!");
			return 0;
		}
		if(!packet.send_packet_key1(Dlg->m_adapterHandle,captured,Dlg->m_MacAdd))
		{
			Dlg->ChgBtn(TRUE,"��ӦEAPOL-Key1 ������!");
			Dlg->AddLog("��ӦEAPOL-Key1 ������!");
			return 0;
		}
		if(!packet.send_packet_key2(Dlg->m_adapterHandle,captured,Dlg->m_MacAdd))
		{
			Dlg->ChgBtn(TRUE,"��ӦEAPOL-Key2 ������!");
			Dlg->AddLog("��ӦEAPOL-Key2 ������!");
			return 0;
		}
		Dlg->AddLog("�������� EAPOL-Key ����ά������");
	}

    return 0;
}

//========================OnLogoff======================================
void CLuzj_ZTEDlg::OnLogoff() 
{
	CPacket packet;
	packet.send_packet_logoff(m_adapterHandle,m_MacAdd);

	this->ChgBtn(TRUE);

	m_bAuth=FALSE;

	//�ȴ������500ms��û���Զ��˳�����ǿ�ƽ���
	if (::WaitForSingleObject(this->m_AuthThread,500) == WAIT_TIMEOUT)	
	{
		::TerminateThread(this->m_AuthThread ,0);
	}

	TCHAR tempBuffer[MAX_STRING];
	CString strSystemDirectory;
	GetSystemDirectory( tempBuffer, MAX_STRING);
	strSystemDirectory.Format(_T("%s\\ipconfig.exe"),tempBuffer);
	SHELLEXECUTEINFO ShExecInfo = {0};
	ShExecInfo.cbSize	= sizeof(SHELLEXECUTEINFO);
	ShExecInfo.fMask		= SEE_MASK_NOCLOSEPROCESS;
	ShExecInfo.lpFile		= strSystemDirectory;		
	ShExecInfo.lpParameters = _T("/release");	
	ShExecInfo.nShow	= SW_HIDE;	
	ShellExecuteEx(&ShExecInfo);
//	int iRnt =WaitForSingleObject(ShExecInfo.hProcess,30000);

	m_StatusBar.SetText("        ״̬: �Ѿ�����!",1,0);
	this->AddLog("�Ѿ�����!");
}
//========================OnLogoff======================================


//========================getUserInfo======================================
void CLuzj_ZTEDlg::getUserInfo()
{
	UpdateData();
	m_usernameLen=m_user.GetLength();
	m_passwordLen=m_pass.GetLength();
	int i=0,j=0;
	while(i<m_usernameLen)
	{
		m_username[i++]=m_user.GetAt(i);
	}
	while(j<m_passwordLen)
	{
		m_password[j++]=m_pass.GetAt(j);
	}
}
//========================getUserInfo======================================


//////////////////////////////////////////////////////////////////////////
//��Ӧ�˳���ť������Ѿ���֤�����ȷ����˳���֤��
void CLuzj_ZTEDlg::OnExit() 
{
	ShowWindow(SW_HIDE);
	if (m_bAuth)
	{
		m_bAuth=!m_bAuth;
		this->OnLogoff();
	}
	CDialog::OnOK();
}
//////////////////////////////////////////////////////////////////////////


void CLuzj_ZTEDlg::OnTimer(UINT nIDEvent)
{
	time_t t =time(NULL);
	char szTime[MAX_STRING];
	strftime(szTime,MAX_STRING,"  %Hʱ%M��%S��",localtime(&t));
	m_StatusBar.SetText(szTime,0,0);

	if (m_bAuth)
	{
		t -= m_startTime;
		strftime(szTime,MAX_STRING,"        ״̬:  �Ѿ�����%Hʱ%M��%S��",gmtime(&t));
		m_StatusBar.SetText(szTime,1,0);
	}
	else
	{
		m_StatusBar.SetText("        ״̬:  δ����",1,0);
	}
	CDialog::OnTimer(nIDEvent);
}

void CLuzj_ZTEDlg::OnLogshow() 
{
	static bShow=TRUE;
	RECT rc1={0},rc2={0};
	if (bShow)
	{
		GetDlgItem(IDC_SPLIT)->GetWindowRect(&rc1);
		GetWindowRect(&m_rc);
		rc2=m_rc;
		rc2.right=rc1.left-2;
		MoveWindow(&rc2,TRUE);
		bShow=!bShow;
		GetDlgItem(IDC_LOGSHOW)->SetWindowText("��־>>");
	}
	else
	{
		GetWindowRect(&rc1);
		
		m_rc.right+=rc1.left-m_rc.left;
		m_rc.bottom+=rc1.top-m_rc.top;
		m_rc.left=rc1.left;
		m_rc.top=rc1.top;

		MoveWindow(&m_rc,TRUE);
		bShow=!bShow;
		GetDlgItem(IDC_LOGSHOW)->SetWindowText("��־<<");
	}
}

void CLuzj_ZTEDlg::OnSelchangeUsername() 
{
	CString str;
	m_ccb_username.GetLBText(m_ccb_username.GetCurSel(),str);

	userInfo user;
	int i=0,k=0;
	i=Config.m_UserInfo.GetCount();
	for (k=0;k<i;k++)
	{
		Config.m_UserInfo.Lookup(k,user);
		if (user.user==str)
		{
			GetDlgItem(IDC_PWD)->SetWindowText(user.pass);
			break;
		}
	}
}

void CLuzj_ZTEDlg::OnTest() 
{
//	char szTemp[MAX_STRING];

/*
	MIB_IFTABLE *pIfTable; 
    MIB_IFROW *pIfRow; 
	pIfTable = (MIB_IFTABLE *) malloc(sizeof (MIB_IFTABLE)); 
	DWORD len=sizeof(MIB_IFTABLE);
	if (GetIfTable(pIfTable,&len,TRUE) == ERROR_INSUFFICIENT_BUFFER)
	{
		free(pIfTable); 
		pIfTable = (MIB_IFTABLE *)malloc(len);
	}
	if (GetIfTable(pIfTable,&len,TRUE)==NO_ERROR)
	{
		MessageBox("OK");
		for (int i=0;i<pIfTable->dwNumEntries;i++)
		{
				//if (pIfTable->table[i].dwOperStatus==MIB_IF_OPER_STATUS_CONNECTED)
				//{
					sprintf(szTemp,"%d",pIfTable->table[i].dwOperStatus);
					MessageBox(szTemp);
				//}
		}
	}

	//����������Ϣ
	char m_errorBuffer[ PCAP_ERRBUF_SIZE ];		//������Ϣ������
	pcap_if_t		* allAdapters;				//�������б�
	if(pcap_findalldevs(&allAdapters, m_errorBuffer) == -1 || allAdapters == NULL)
	{
		MessageBox("��ȡ������Ϣʧ�ܣ���ȷ���㰲װ��WinPcap!","����",MB_ICONERROR|MB_OK);
		pcap_freealldevs(allAdapters);
		CDialog::OnCancel();
	}
	
	pcap_if_t* adapter;//��ʱ���������
    for(adapter = allAdapters; adapter != NULL; adapter = adapter->next)
    {
		MessageBox(adapter->description);
    }
	pcap_freealldevs(allAdapters);

*/
}

void CLuzj_ZTEDlg::OnSetting() 
{
	CSettingDlg dlg;
	if (dlg.DoModal())
	{
	}
}
