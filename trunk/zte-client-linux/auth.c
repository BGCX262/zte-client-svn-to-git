/* File: auth.c
 * ------------
 * 注：核心函数为Authenticaiton()，由该函数执行801.1X认证
 */

int Authenticaiton(const char *UserName, const char *Password, const char *DeviceName);

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <stdbool.h>

#include "pcap.h"

#include <unistd.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <arpa/inet.h>


#include "debug.h"
#include "md5.h"
#include "rc4.h"
typedef uint8_t u_char;



	//以下为数据包初始化并发送的函数
static int send_packet_start(pcap_t * adapterHandle,u_char* MacAdd);						//此为开始的包

static int send_packet_logoff(pcap_t * adapterHandle,u_char* MacAdd);						//此为退出的包

static int send_packet_response_Identity(pcap_t * adapterHandle,const u_char * captured,u_char* MacAdd
									,const char * m_username,int m_usernameLen);				//此为回应系统的request包

static int send_packet_response_MD5(pcap_t * adapterHandle,const u_char* captured,u_char* MacAdd
		,const char * m_username,int m_usernameLen,const char * m_password,int m_passwordLen);	//此为回应系统的MD5-Challenge包

static int send_packet_key1(pcap_t * adapterHandle,const u_char* captured,u_char* MacAdd);		//连接维持包1

static int send_packet_key2(pcap_t * adapterHandle,const u_char* captured,u_char* MacAdd);		//连接维持包2
		
		
		
		
		
		

static void GetMacFromDevice(uint8_t mac[6], const char *devicename);

extern void FillMD5Area(uint8_t digest[],
	       	uint8_t id, const char passwd[], const uint8_t srcMD5[]);


/**
 * 函数：Authenticaiton()
 *
 * 使用以太网进行802.1X认证(802.1X Authentication)
 * 该函数将不断循环，应答802.1X认证会话，直到遇到错误后才退出
 */

int Authenticaiton(const char *UserName, const char *Password, const char *DeviceName)
{
	char			errbuf[PCAP_ERRBUF_SIZE];
	pcap_t*		adhandle; // adapter handle
	uint8_t		MAC[6];
	char			FilterStr[100];
	struct 		bpf_program	fcode;
	const int DefaultTimeout=1000;//设置接收超时参数，单位ms

	/* 打开适配器(网卡) */
	adhandle = pcap_open_live(DeviceName,65536,1,DefaultTimeout,errbuf);
	if (adhandle==NULL) {
		fprintf(stderr, "%s\n", errbuf); 
		exit(-1);
	}

	/* 查询本机MAC地址 */
	GetMacFromDevice(MAC, DeviceName);

	/*
	 * 设置过滤器：
	 * 初始情况下只捕获发往本机的802.1X认证会话，不接收多播信息（避免误捕获其他客户端发出的多播信息）
	 * 进入循环体前可以重设过滤器，那时再开始接收多播信息
	 */
	sprintf(FilterStr, "(ether proto 0x888e) and (ether dst host %02x:%02x:%02x:%02x:%02x:%02x)",
							MAC[0],MAC[1],MAC[2],MAC[3],MAC[4],MAC[5]);
	pcap_compile(adhandle, &fcode, FilterStr, 1, 0xff);
	pcap_setfilter(adhandle, &fcode);



	int retcode;
	struct pcap_pkthdr *header;
	const uint8_t	*captured;


	/* 主动发起认证会话 */
	send_packet_start(adhandle, MAC);
	DPRINTF("Client: Start.\n");

///*
	// 等待认证服务器的回应 
	bool serverIsFound = false;
	while (!serverIsFound)
	{
		retcode = pcap_next_ex(adhandle, &header, &captured);
		if (retcode==1)
			serverIsFound = true;
		else
		{	// 延时后重试
			sleep(5); DPRINTF(".");
			send_packet_start(adhandle, MAC);
			// NOTE: 这里没有检查网线是否接触不良或已被拔下
		}
	}

//*/


	send_packet_response_Identity(adhandle,captured, MAC,UserName,strlen(UserName));
	DPRINTF("Client: EAP-Identity.\n");
	
	

	
	
	
///*
	
	serverIsFound = false;
	while (!serverIsFound)
	{
		retcode = pcap_next_ex(adhandle, &header, &captured);
		if (retcode==1)
			serverIsFound = true;
		else
		{	// 延时后重试
			sleep(5); DPRINTF(".");
			send_packet_start(adhandle, MAC);
			// NOTE: 这里没有检查网线是否接触不良或已被拔下
		}
	}
//*/		
	
	send_packet_response_MD5(adhandle,captured,MAC,
									UserName,strlen(UserName),Password,strlen(Password));

	DPRINTF("Client: MD5-Challenge.\n");

	DPRINTF("Server: Success. packet id [%d] \n", captured[19]);
	// 刷新IP地址
	system("dhclient");

	// 进入循环体
	while(1)
	{
		// 调用pcap_next_ex()函数捕获数据包
		while (pcap_next_ex(adhandle, &header, &captured) != 1)
		{
			DPRINTF("."); // 若捕获失败，则等1秒后重试
			sleep(5);     // 直到成功捕获到一个数据包后再跳出
			// NOTE: 这里没有检查网线是否已被拔下或插口接触不良
		}

		send_packet_key1(adhandle,captured,MAC);
		send_packet_key2(adhandle,captured,MAC);
	}
	return (0);
}



static
void GetMacFromDevice(uint8_t mac[6], const char *devicename)
{
	int			fd;
	int			err;
	struct 	ifreq	ifr;
	fd = socket(PF_PACKET, SOCK_RAW, htons(0x0806));
	assert(fd != -1);
	assert(strlen(devicename) < IFNAMSIZ);
	strncpy(ifr.ifr_name, devicename, IFNAMSIZ);
	ifr.ifr_addr.sa_family = AF_INET;
	err = ioctl(fd, SIOCGIFHWADDR, &ifr);
	assert(err != -1);
	memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
	err = close(fd);
	assert(err != -1);
	return;
}


//======================packet_start======================================
static int send_packet_start(pcap_t * adapterHandle,u_char* MacAdd)
{
	u_char packet_start[]={
					0x01,0x80,0xc2,0x00,0x00,0x03,			//对方MAC
					0x00,0x00,0x00,0x00,0x00,0x00,			//自己MAC
					0x88,0x8e,0x01,0x01,0x00,0x00	};

	memcpy(packet_start+6,MacAdd,6);

	if(pcap_sendpacket(adapterHandle, packet_start,18)!=0)
    {
        return 0;
    }
	return 1;
}
//======================packet_start======================================


//======================packet_logoff======================================
static int send_packet_logoff(pcap_t * adapterHandle,u_char* MacAdd)
{
	u_char packet_logoff[100]={
		0x01,0x80,0xc2,0x00,0x00,0x03,			//对方MAC
		0x00,0x00,0x00,0x00,0x00,0x00,						//自己MAC
		0x88,0x8e,0x01,0x02,0x00,0x00	};

	memcpy(packet_logoff+6,MacAdd,6);

	if(pcap_sendpacket(adapterHandle, packet_logoff,18)!=0)
    {
        return 0;
    }
	return 1;
}
//======================packet_logoff======================================




//======================packet_response_Identity======================================
static int send_packet_response_Identity(pcap_t * adapterHandle,const u_char * captured,u_char* MacAdd
											,const char * m_username,int m_usernameLen)
{
	u_char packet_response_Identity[100]={	
					0x01,0x80,0xc2,0x00,0x00,0x03,			//对方MAC
					0x00,0x00,0x00,0x00,0x00,0x00,			//自己MAC
					0x88,0x8e,								//网络协议类型
					0x01,									//Version: 1
					0x00,									//Type: EAP Packet (0)
					0x00,0x11,								//长度，十六进制11代表10进制的17
					0x02,									//Code: Response (2)
					0x00,									//Id: 由发来的包决定
					0x00,0x11,								//Length: 17
					0x01,									//Type: Identity [RFC3748] (1)
					0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00  //存放自己的账号，是ascii码，我校账号长度为11
				};

	memcpy(packet_response_Identity+6,MacAdd,6);

	//来自request包的id
	packet_response_Identity[19]=captured[19];

	int i=0;
	//设置登录的账号
	for (i=0;i<m_usernameLen;i++)
	{
		packet_response_Identity[23+i]=m_username[i];
	}

	if(pcap_sendpacket(adapterHandle, packet_response_Identity,23+m_usernameLen)!=0)
    {
        return 0;
    }
	return 1;
}
//======================packet_response_Identity======================================


//======================packet_response_MD5======================================
static int send_packet_response_MD5(pcap_t * adapterHandle,const u_char* captured,u_char* MacAdd
									   ,const char *	m_username,int m_usernameLen,const char * m_password,int	m_passwordLen)
{	
	u_char packet_response_MD5[100]={	
					0x01,0x80,0xc2,0x00,0x00,0x03,			//对方MAC
					0x00,0x00,0x00,0x00,0x00,0x00,			//自己MAC
					0x88,0x8e,								//类型
					0x01,									//Version: 1
					0x00,									//Type: EAP Packet (0)
					0x00,0x22,								//长度，22代表10进制的34
					0x02,									//Code: Response (2)
					0x36,									//Id: 54
					0x00,0x22,								//Length: 34
					0x04,									//Type: MD5-Challenge [RFC3748] (4)
					0x10,									//Value-Size: 16
					0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	//16字节的MD5的前8字节
					0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	//16字节的MD5的后8字节
					0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00  //存放自己的账号，是ascii码，我校账号长度为11
				};

	memcpy(packet_response_MD5+6,MacAdd,6);

	//MD5-Challenge的包ID
	packet_response_MD5[19]=captured[19];


/////////////////////////////////////////////////////////////////////
//生成MD5
	u_char MD5Res[16];
	MD5_CTX context;
	u_char	msgbuf[128]={0};
	int i=0,j=0;
	
	//以下是MD5-Challenge的包ID
	msgbuf[i++]=captured[19];
	
	//以下是登陆密码
	while (j<m_passwordLen)
	{
		msgbuf[i++]=m_password[j++];
	}	
	
	//以下是常量zte142052
	u_char temp[]={0x7a,0x74,0x65,0x31,0x34,0x32,0x30,0x35,0x32};
	memcpy(msgbuf+i,temp,9);
	i+=9;
	
	//服务器发来的MD5-Challenge
	memcpy(msgbuf+i,captured+24,16);
	i+=16;
	
	
	MD5Init(&context);
	MD5Update(&context, msgbuf, i);
	MD5Final(MD5Res, &context);
	
/////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////


	//MD5-Challenge:
	memcpy(packet_response_MD5+24,MD5Res,16);

	//以下是登陆的账号
	for (i=0;i<m_usernameLen;i++)
	{
		packet_response_MD5[40+i]=m_username[i];
	}


	if(pcap_sendpacket(adapterHandle, packet_response_MD5,40+m_usernameLen)!=0)
    {
        return 0;
    }
	return 1;
}
//======================packet_response_MD5======================================


//======================packet_key1======================================
static int send_packet_key1(pcap_t * adapterHandle,const u_char* captured,u_char* MacAdd)
{
	u_char packet_key1[100]={	
					0x01,0x80,0xc2,0x00,0x00,0x03,				//对方MAC
					0x00,0x00,0x00,0x00,0x00,0x00,				//自己MAC
					0x88,0x8e,									//类型
					0x01,										//Version: 1
					0x03,										//Type: EAP Packet (3)
					0x00,0x3c,									//长度，3c代表10进制的60
					0x01,										//Descriptor Type: RC4 Descriptor (1)
					0x00,0x10,									//key length
					0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	//Replay Counter: 8字节
					0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	//16字节的Key IV 前8字节
					0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	//16字节的Key IV 后8字节
					0x00,										//index	
					0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	//16字节的Key Signature 前8字节
					0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	//16字节的Key Signature 后8字节
					0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	//16字节的Key 前8字节
					0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	//16字节的Key 后8字节
			};


	//MAC
	memcpy(packet_key1+6,MacAdd,6);

	//Replay Counter  +  Key IV 原样复制，24字节
	memcpy(packet_key1+21,captured+21,24);

	//此包的index值，直接从接收包复制过来
	packet_key1[45]=captured[45];
	
	//////////////////////////////////////////////////////////////////////////
	//使用rc4算法生成Key，基于（Key IV + Key IV最后四个字节）==20字节
	u_char enckey[]={0x02,0x0E,0x05,0x04,0x66,0x40,0x19,0x75
					,0x06,0x06,0x00,0x16,0xD3,0xF3,0xAC,0x02
	};
	// 	u_char enckey[]={0x02,0x0E,0x05,0x04,0xD5,0x40,0x19,0x75
	// 		,0x06,0x06,0x00,0x13,0x77,0x4C,0x4E,0xAB
	// 	};
	u_char wholekey[20];
	memcpy(wholekey,captured+29,16);
	memcpy(wholekey+16,captured+41,4);
	int keylen=16;
	struct rc4_state s;
	rc4_setup( &s, wholekey, 20 );
    rc4_crypt( &s, enckey, keylen );
	memcpy(&packet_key1[62],enckey,16);

	//////////////////////////////////////////////////////////////////////////
	//使用hmac_md5算法生成Key Signature，此用于包的校验
	u_char deckey[64]={0};
	u_char encDat[64];
	memcpy(encDat,packet_key1+14,64);
	enckey[0]=packet_key1[45];
	hmac_md5(encDat,64,enckey,1,deckey);
	memcpy(packet_key1+46,deckey,16);

	if(pcap_sendpacket(adapterHandle, packet_key1,78)!=0)
    {
        return 0;
    }
	return 1;
}
//======================packet_key1======================================


//======================packet_key2======================================
static int send_packet_key2(pcap_t * adapterHandle,const u_char* captured,u_char* MacAdd)
{
	u_char packet_key2[100]={
					0x01,0x80,0xc2,0x00,0x00,0x03,				//对方MAC
					0x00,0x00,0x00,0x00,0x00,0x00,				//自己MAC
					0x88,0x8e,									//类型
					0x01,										//Version: 1
					0x03,										//Type: EAP Packet (3)
					0x00,0x30,									//长度，3c代表10进制的48
					0x01,										//Descriptor Type: RC4 Descriptor (1)
					0x00,0x04,									//key length
					0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	//Replay Counter: 8字节
					0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	//16字节的Key IV 前8字节
					0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	//16字节的Key IV 后8字节
					0x00,										//index	
					0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	//16字节的Key Signature 前8字节
					0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	//16字节的Key Signature 后8字节
					0x00,0x00,0x00,0x00							//4字节的Key
			};
	
	//MAC
	memcpy(packet_key2+6,MacAdd,6);
	
	//Replay Counter  +  Key IV 原样复制，24字节
	memcpy(packet_key2+21,captured+21,24);
	
	//此包的index值，直接从接收包复制过来
	packet_key2[45]=captured[45];


	//////////////////////////////////////////////////////////////////////////
	//使用rc4算法生成Key，基于（Key IV + Key IV最后四个字节）==20字节
	u_char enckey[]={0x02,0x02,0x14,0x00};
	u_char wholekey[20];
	memcpy(wholekey,captured+29,16);
	memcpy(wholekey+16,captured+41,4);
	int keylen=4;
	u_char deckey[64]={0};
	struct rc4_state s;
	rc4_setup( &s, wholekey, 20 );
    rc4_crypt( &s, enckey, keylen );
	memcpy(packet_key2+62,enckey,4);

	//////////////////////////////////////////////////////////////////////////
	//使用hmac_md5算法生成Key Signature，此用于包的校验	
	u_char encDat[64];
	memcpy(encDat,packet_key2+14,52);
	enckey[0]=packet_key2[45];
	hmac_md5(encDat,52,enckey,1,deckey);
	memcpy(packet_key2+46,deckey,16);


	if(pcap_sendpacket(adapterHandle, packet_key2,66)!=0)
    {
        return 0;
    }
	return 1;
}
//======================packet_key2======================================
