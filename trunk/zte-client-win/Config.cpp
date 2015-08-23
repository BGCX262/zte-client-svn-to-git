
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


// Config.cpp: implementation of the CConfig class.
//
//////////////////////////////////////////////////////////////////////

#include "stdafx.h"
#include "Luzj_ZTE.h"
#include "Config.h"

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[]=__FILE__;
#define new DEBUG_NEW
#endif

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////
CConfig Config;





CConfig::CConfig():m_UserInfo(16)
{

}

CConfig::~CConfig()
{

}

//ȡ��·��
void CConfig::GetFullPathToFile(char  *pszFullPath,char * pszFilename)
{
	GetModuleFileName(GetModuleHandle(NULL), pszFullPath, MAX_STRING);
	strcpy(strrchr(pszFullPath, '\\') + 1, pszFilename);
}


void CConfig::SvaeConfig()
{
	//�������õ��ļ���ȥ
	char pszFullPath[MAX_STRING];
	char pszFilename[MAX_STRING]=CONFIGNAME;
	char szTemp[MAX_STRING];
	GetFullPathToFile(pszFullPath,pszFilename);
	
	sprintf(szTemp,"%d",m_iTimeout);
	WritePrivateProfileString("config","Timeout",szTemp,pszFullPath);

	//�����Ƿ��Զ���������
	m_bRememberPWD==TRUE?WritePrivateProfileString("config","RememberPWD","1",pszFullPath)
						:WritePrivateProfileString("config","RememberPWD","0",pszFullPath);
	
	//�����Ƿ񿪻��Զ�����
	m_bAutorun==TRUE?WritePrivateProfileString("config","Autorun","1",pszFullPath)
					:WritePrivateProfileString("config","Autorun","0",pszFullPath);
	//�����Ƿ��Զ���¼
	m_bAutologon==TRUE?WritePrivateProfileString("config","Autologon","1",pszFullPath)
					  :WritePrivateProfileString("config","Autologon","0",pszFullPath);

	m_bShowBubble==TRUE?WritePrivateProfileString("config","ShowBubble","1",pszFullPath)
					  :WritePrivateProfileString("config","ShowBubble","0",pszFullPath);

	HKEY hRun;
	LONG kResult = ::RegOpenKeyEx(	HKEY_LOCAL_MACHINE ,
									"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
									NULL ,KEY_ALL_ACCESS ,&hRun);
	if (m_bAutorun == TRUE)		//���ÿ����Զ�����
	{
		char szTemp[MAX_STRING],pjPath[MAX_STRING];

		DWORD regsz=REG_SZ;
		DWORD iPathLen;

		strcpy(pszFilename,AfxGetApp()->m_pszExeName);
		strcat(pszFilename,".exe");
		GetFullPathToFile(szTemp,pszFilename);
		sprintf(pjPath,"\"%s\"",szTemp);

	
		iPathLen = (strlen(szTemp) +1) *sizeof(char);
		kResult =::RegQueryValueEx(hRun ,"LuzjZte",NULL ,&regsz ,(BYTE *)szTemp ,&iPathLen);
		if (kResult!=ERROR_SUCCESS || strcmp(szTemp,pjPath)!=0)
		{
			iPathLen = (strlen(pjPath) +1) *sizeof(char);
			kResult =::RegSetValueEx(hRun ,"LuzjZte",NULL ,REG_SZ ,(BYTE *)pjPath ,iPathLen);
		}

	}
	else
	{
		RegDeleteValue(hRun,"LuzjZte");
	}
	::RegCloseKey(hRun);






	//������ѡ������
	WritePrivateProfileString("config","netcard",m_csNetCard,pszFullPath);


	
	//��ȡ�����˺��������
	CString str="";
	userInfo user;
	int i=0,k=0;
	i=Config.m_UserInfo.GetCount();
	for (k=0;k<i;k++)
	{
		Config.m_UserInfo.Lookup(k,user);
		WritePrivateProfileString("config",user.user,user.pass,pszFullPath);
		if (k==0)
		{
			str=user.user;
		}
		else
		{
			str=user.user+"|"+str;
		}
	}
	WritePrivateProfileString("config","username",str,pszFullPath);

	WritePrivateProfileString("config","LastUser",m_csLastUser,pszFullPath);



}
void CConfig::LoadConfig()
{

	//�������ļ��ж�ȡ����
	char pszFullPath[MAX_STRING];
	char pszFilename[MAX_STRING]=CONFIGNAME;
	GetFullPathToFile(pszFullPath,pszFilename);
	

	int retCode;
	m_iTimeout=GetPrivateProfileInt("config","Timeout",30,pszFullPath);
	//��ȡ�Ƿ��Զ���������,Ĭ��Ϊ��
	retCode=GetPrivateProfileInt("config","RememberPWD",1,pszFullPath);
	m_bRememberPWD=(retCode==1?TRUE:FALSE);

	//��ȡ�Ƿ񿪻��Զ�����,Ĭ��Ϊ��
	retCode=GetPrivateProfileInt("config","Autorun",0,pszFullPath);
	m_bAutorun=(retCode==1?TRUE:FALSE);

	//��ȡ�Ƿ��Զ���¼
	retCode=GetPrivateProfileInt("config","Autologon",0,pszFullPath);
	m_bAutologon=(retCode==1?TRUE:FALSE);


	retCode=GetPrivateProfileInt("config","ShowBubble",1,pszFullPath);
	m_bShowBubble=(retCode==1?TRUE:FALSE);


	//��ȡ�����˺��������
	char szTemp[MAX_STRING],szPass[MAX_STRING];
	GetPrivateProfileString("config","LastUser","",szTemp,MAX_STRING,pszFullPath);
	m_csLastUser=szTemp;
	GetPrivateProfileString("config","username","",szTemp,MAX_STRING,pszFullPath);
	char *seps= "|";
	char *token;
	int i=0,k=0;
	userInfo user;
	token = strtok(szTemp, seps);
	while( token != NULL )
	{
		GetPrivateProfileString("config",token,"",szPass,MAX_STRING,pszFullPath);
		user.user=token;
		user.pass=szPass;
		m_UserInfo.SetAt(i,user);
		token = strtok( NULL, seps );	
		i++;
	}


	//��ȡ�ϴ���ѡ����������
	GetPrivateProfileString("config","netcard","",szTemp,MAX_STRING,pszFullPath);
	m_csNetCard=szTemp;


/*	
	CString   strName;   
	m_UserInfo.Lookup("118532007029",strName);
	
	if (strName=="")
	{
		MessageBox(NULL,"NULL","",MB_OK);
	} 
	else
	{
		MessageBox(NULL,strName,"",MB_OK);
	}
*/





}
void CConfig::LoadDefaultConfig()
{

}
