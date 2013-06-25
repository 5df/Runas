#include <stdio.h>
#include <stdlib.h>

#define _WIN32_WINNT  0x0600
#define WINVER  0x0500

#include <windows.h>
#include <Wtsapi32.h>
#include <Userenv.h>

BOOL
getActiveConsoleId(LPDWORD id){
    PWTS_SESSION_INFO sessioninfo;
    DWORD count;
    DWORD i;

    if( ! WTSEnumerateSessions(WTS_CURRENT_SERVER_HANDLE,   //  _In_   HANDLE hServer,
                               0,                           //  _In_   DWORD Reserved,
                               1,                           //  _In_   DWORD Version,
                               &sessioninfo,                //  _Out_  PWTS_SESSION_INFO *ppSessionInfo,
                               &count))                     //  _Out_  DWORD *pCount
    {
        return FALSE;
    }
    else{
        /* Find the active session */
        for(i=0;i<count;i++){
            if(sessioninfo[i].State==WTSActive){
                *id=sessioninfo[i].SessionId;
                break;
            }
        }
    }
    WTSFreeMemory(&sessioninfo);
    return TRUE;
}

int main(int argc, char *argv[])
{
    /** VARS **/
    int error;
    BOOL elevated;
    FILE *log;
    char logfile[128];
    DWORD sessionid;
    DWORD i;
    HANDLE hToken;
    char *username;
    DWORD usersize;
    char *programname;
    LPVOID env;
    PROFILEINFO profile;
    /* Information about window station,
     * desktop, standard handles, and appearance
     * of the main window for a process creation
     */
    STARTUPINFO startupinfo;
    PROCESS_INFORMATION processinfo;

    LUID luid;
    TOKEN_PRIVILEGES tp;
    HANDLE hTokenDup;
    HANDLE hProcess;

    /** INIT **/
    error=0;
    elevated=FALSE;
    log=NULL;
    hToken=NULL;
    usersize=0;
    env=NULL;
    ZeroMemory(&profile, sizeof(profile));
    /* Init the startup info */
    ZeroMemory(&startupinfo, sizeof(startupinfo));
    /* Init the process info */
    ZeroMemory(&processinfo, sizeof(processinfo));

    /** START **/
    if(argc < 2){
        printf("Usage: %s [-e] <program>\n\t-e: evelated active session user\n\t",argv[0]);
        exit(1);
    }

    snprintf(logfile,128,"%s.log.txt",argv[0]);
    programname=argv[argc-1];

    log = fopen(logfile,"a+");
    if(!log){
        /* not realy an error ... */
        log=stdout;
    }

    fprintf(log,"-- %s start --\n",argv[0]);

    for(i=1;i<argc-1;i++){
        if(!strncmp(argv[i],"-e",2)){
            elevated=TRUE;
        }
        else {
            fprintf(log,"[!] Unknow option: %s\n",argv[i]);
            error++;
            goto abort;
        }
    }
    if(elevated)
        fprintf(log,"[+] Elevation: on\n");
    else
        fprintf(log,"[+] Elevation: off\n");


    if( ! getActiveConsoleId(&sessionid)){
        fprintf(log,"[-] WTSEnumerateSessions: %ld, error\n",GetLastError());
        error++;
        goto abort;
    }
    else {
        fprintf(log,"[+] WTSEnumerateSessions: ok\n");
    }

    /* Get session info */
    if( ! WTSQuerySessionInformation(WTS_CURRENT_SERVER_HANDLE,
                               sessionid,
                               WTSUserName,
                               &username,
                               &usersize
                               ))
    {
        fprintf(log,"[-] WTSQuerySessionInformation: %ld, error\n",GetLastError());
        error++;
        goto abort;
    }
    else {
        fprintf(log,"[+] WTSQuerySessionInformation: ok\n\tUSER:%s\n",username);
    }

    /* Get a primary identification Token */
    if(elevated){
        hProcess=GetCurrentProcess();
        if( ! OpenProcessToken(hProcess,                //   _In_   HANDLE ProcessHandle,
                                TOKEN_ALL_ACCESS, //   _In_   DWORD DesiredAccess,
                                hToken))               //            _Out_  PHANDLE TokenHandle
        {
            fprintf(log,"[-] OpenProcessToken: %ld, error\n",GetLastError());
            error++;
            goto abort;
        }
        else{
            fprintf(log,"[+] OpenProcessToken: ok\n");
        }
    }
    else{
        /* Get the session acess token */
        if( ! WTSQueryUserToken(sessionid, &hToken)){
            fprintf(log,"[-] WTSQueryUserToken: %ld, error\n",GetLastError());
            error++;
            /* can't recover, needed to load user profile */
            goto abort;
        }
        else {
            fprintf(log,"[+] WTSQueryUserToken: ok\n");
        }
    }

    /* Create a new identification token */
    if( ! DuplicateTokenEx(hToken,
                           MAXIMUM_ALLOWED,NULL,
                           SecurityIdentification,
                           TokenPrimary,
                           &hTokenDup))
    {
        fprintf(log,"[-] DuplicateTokenEx: %ld, error\n",GetLastError());
        error++;
        goto abort;
    }
    else{
        fprintf(log,"[+] DuplicateTokenEx: ok\n");
    }

    if(elevated){
            /* Get debug privilege LUID */
            if (!LookupPrivilegeValue(NULL,             // _In_opt_  LPCTSTR lpSystemName,
                                      SE_DEBUG_NAME,    // _In_      LPCTSTR lpName,
                                      &luid))           // _Out_     PLUID lpLuid
            {
               fprintf(log,"[-] LookupPrivilegeValue: %ld, error\n",GetLastError());
               error++;
               goto abort;
            }
            else{
                fprintf(log,"[+] LookupPrivilegeValue: ok\n");
            }
            tp.PrivilegeCount=1;
            tp.Privileges[0].Luid=luid;
            if( ! SetTokenInformation(hTokenDup,TokenSessionId,(void*)&sessionid,sizeof(sessionid))){
                fprintf(log,"[-] SetTokenInformation: %ld, error\n",GetLastError());
                error++;
            }
            else{
                fprintf(log,"[+] SetTokenInformation: ok\n");
            }
            /* Elevate token privileges */
            if (!AdjustTokenPrivileges(hTokenDup,FALSE,&tp,sizeof(TOKEN_PRIVILEGES),
                        (PTOKEN_PRIVILEGES)NULL,NULL))
            {
               fprintf(log,"[-] AdjustTokenPrivilege: %ld, error\n",GetLastError());
               error++;
            }
            else{
                fprintf(log,"[+] AdjustTokenPrivilege: ok\n");
            }
    }
    /* Retrive user environnement
     */
    if( ! CreateEnvironmentBlock(&env,    //  _Out_     LPVOID *lpEnvironment,
                           hToken,  //  _In_opt_  HANDLE hToken,
                           FALSE    //  _In_      BOOL bInherit
                           ))
    {
        fprintf(log,"[-] CreateEnvironmentBlock: %ld, error\n",GetLastError());
        env=NULL;
        error++;
    }
    else {
        fprintf(log,"[+] CreateEnvironmentBlock: ok\n");
    }

    /* Load the profile info aka HKEY_USER
     * This is only needed when impersonating a user
     * Else the current user profile info is used by the new process
     * TODO: load itinerant (net) profile
     */
    profile.dwSize=sizeof(profile);
    profile.lpUserName=username;
    if( ! LoadUserProfile(hToken,&profile)){
        fprintf(log,"[-] LoadUserProfile: %ld, error\n",GetLastError());
        profile.dwSize=0;
        error++;
    }
    else {
        fprintf(log,"[+] LoadUserProfile: ok\n");
    }

    /* Choose appropriate desktop */
    startupinfo.cb=sizeof(startupinfo);
    startupinfo.lpDesktop=TEXT("winsta0\\default"); // to get the desktop

    /* Create the new process
     * BOOL WINAPI CreateProcessAsUser
     */
    if( ! CreateProcessAsUser(hTokenDup,         //  _In_opt_     HANDLE hToken,
                        programname,    //  _In_opt_     LPCTSTR lpApplicationName,
                        NULL,           //  _Inout_opt_  LPTSTR lpCommandLine,
                        NULL,           //  _In_opt_     LPSECURITY_ATTRIBUTES lpProcessAttributes,
                        NULL,           //  _In_opt_     LPSECURITY_ATTRIBUTES lpThreadAttributes,
                        FALSE,          //  _In_         BOOL bInheritHandles,
                        NORMAL_PRIORITY_CLASS|  //  _In_         DWORD dwCreationFlags,
                        CREATE_UNICODE_ENVIRONMENT|
                        CREATE_NEW_CONSOLE,
                        env,            //  _In_opt_     LPVOID lpEnvironment,
                        NULL,         //  _In_opt_     LPCTSTR lpCurrentDirectory,
                        &startupinfo,   //  _In_         LPSTARTUPINFO lpStartupInfo,
                        &processinfo    //  _Out_        LPPROCESS_INFORMATION lpProcessInformation
                        ))
    {
        fprintf(log,"[-] CreateProcessAsUser: %ld, error\n\tPROGRAM:%s\n",GetLastError(),programname);
        error++;
    }
    else{
        fprintf(log,"[+] CreateProcessAsUser: ok\n\tPROGRAM:%s\n",programname);
    }

abort:
    if(processinfo.hProcess){
         /* Wait the for the child procees death */
        WaitForInputIdle(processinfo.hProcess,INFINITE);
        /* Close the child process handle */
        CloseHandle(processinfo.hProcess);
        CloseHandle(processinfo.hThread);
    }
    if(usersize){
        /* Free username */
        WTSFreeMemory(username);
    }
    if(profile.hProfile){
        /* Unload the profile info */
        UnloadUserProfile(hToken,profile.hProfile);
    }
    if(env){
        /* Close the enviroenement block */
         DestroyEnvironmentBlock(env);
    }
    /* Close the token */
    if(hToken)
        CloseHandle(&hToken);
    if(hTokenDup)
        CloseHandle(&hTokenDup);
    /* Close the log file */
    if(log){
        fprintf(log,"-- %s end --\n",argv[0]);
        fclose(log);
    }
    return error;
}
