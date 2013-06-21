#include <stdio.h>
#include <stdlib.h>

#define _WIN32_WINNT  0x0501

#include <windows.h>

#include <Wtsapi32.h> // WTS...

#include <Userenv.h> // CreateEnvironement

int main(int argc, char *argv[])
{
    int error;
    BOOL impersonate;
    FILE *log;
    char logfile[128];
    PWTS_SESSION_INFO sessioninfo; /* a pointer to an array of WTS_SESSION_INFO */
    DWORD sessionid;
    DWORD count;
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

    error=0;

    if(argc < 2){
        printf("Usage: %s [-i] <program>\n\t-i: impersonate the active session user\n\t",argv[0]);
        error++;
        goto abort;
    }

    snprintf(logfile,128,"%s.log.txt",argv[0]);
    programname=argv[argc-1];

    log = fopen(logfile,"a+");
    if(!log){
        /* not realy an error ... */
        log=stdout;
    }

    fprintf(log,"-- %s start --\n",argv[0]);

    impersonate=FALSE;
    for(i=1;i<argc-1;i++){
        if(!strncmp(argv[i],"-i",2)){
            impersonate=TRUE;
        }
        else {
            fprintf(log,"[!] Unknow option: %s\n",argv[i]);
            error++;
            goto abort;
        }
    }
    if(impersonate)
        fprintf(log,"[+] Impersonation: on\n");
    else
        fprintf(log,"[+] Impersonation: off\n");

    /* Enum open sessions
     * BOOL WTSEnumerateSessions
     */
    if( ! WTSEnumerateSessions(WTS_CURRENT_SERVER_HANDLE,   //  _In_   HANDLE hServer,
                               0,                           //  _In_   DWORD Reserved,
                               1,                           //  _In_   DWORD Version,
                               &sessioninfo,                //  _Out_  PWTS_SESSION_INFO *ppSessionInfo,
                               &count))                     //  _Out_  DWORD *pCount
    {
        fprintf(log,"[-] WTSEnumerateSessions: %ld, error\n",GetLastError());
        error++;
    }
    else{
        /* Find the active session */
        fprintf(log,"[+] WTSEnumerateSessions: ok\n");
        for(i=0;i<count;i++){
            if(sessioninfo[i].State==WTSActive){
                fprintf(log,"\tSESSION ID:%ld STATION NAME:%s\n",sessioninfo[i].SessionId,sessioninfo[i].pWinStationName);
                sessionid=sessioninfo[i].SessionId;

                usersize=0;
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
                }
                else {
                    fprintf(log,"[+] WTSQuerySessionInformation: ok\n\tUSER:%s\n",username);
                }

                /* Get the session acess token
                 * This is only needed when impersonating a user
                 * Else the current user token is used by the new process
                 */
                hToken=NULL;
                if(impersonate)
                {

                    /* Get the session acess token */
                    if( ! WTSQueryUserToken(sessionid, &hToken)){
                        fprintf(log,"[-] WTSQueryUserToken: %ld, error\n",GetLastError());
                        error++;
                        /* can't recover, needed to load user profile */
                        continue;
                    }
                    else {
                        fprintf(log,"[+] WTSQueryUserToken: ok\n");
                    }
                }
                /* Try to create a process */


                /* Retrive user environnement
                 * This is only needed when impersonating another user
                 * Else the current environement is used by the new process
                 */
                env=NULL;
                if(impersonate){
                    //BOOL WINAPI
                    if( ! CreateEnvironmentBlock(&env,    //  _Out_     LPVOID *lpEnvironment,
                                           hToken,  //  _In_opt_  HANDLE hToken,
                                           FALSE    //  _In_      BOOL bInherit
                                           ))
                    {
                        fprintf(log,"[-] CreateEnvironmentBlock: %ld, error\n",GetLastError());
                        error++;
                    }
                    else {
                        fprintf(log,"[+] CreateEnvironmentBlock: ok\n");
                    }
                }

                /* Load the profile info aka HKEY_USER
                 * This is only needed when impersonating a user
                 * Else the current user profile info is used by the new process
                 * TODO: load itinerant (net) profile
                 */
                if(impersonate){
                    //BOOL WINAPI
                    ZeroMemory(&profile, sizeof(profile));
                    profile.dwSize=sizeof(profile);
                    profile.lpUserName=username;
                    if( ! LoadUserProfile(hToken,&profile)){
                        fprintf(log,"[-] LoadUserProfile: %ld, error\n",GetLastError());
                        error++;
                    }
                    else {
                            profile.dwSize=0;
                        fprintf(log,"[+] LoadUserProfile: ok\n");
                    }
                }

                /* Init the startup info */
                ZeroMemory(&startupinfo, sizeof(startupinfo));
                startupinfo.cb=sizeof(startupinfo);
                startupinfo.lpDesktop=TEXT("winsta0\\default"); // to get the desktop

                /* Init the process info */
                ZeroMemory(&processinfo, sizeof(processinfo));

                /* Create the new process */
                if(impersonate){
                    /* BOOL WINAPI CreateProcessAsUser */
                    if( ! CreateProcessAsUser(hToken,         //  _In_opt_     HANDLE hToken,
                                        programname,    //  _In_opt_     LPCTSTR lpApplicationName,
                                        NULL,           //  _Inout_opt_  LPTSTR lpCommandLine,
                                        NULL,           //  _In_opt_     LPSECURITY_ATTRIBUTES lpProcessAttributes,
                                        NULL,           //  _In_opt_     LPSECURITY_ATTRIBUTES lpThreadAttributes,
                                        FALSE,          //  _In_         BOOL bInheritHandles,
                                        NORMAL_PRIORITY_CLASS|  //  _In_         DWORD dwCreationFlags,
                                        CREATE_UNICODE_ENVIRONMENT,
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
                }
                else {
                    //BOOL WINAPI CreateProcess
                    if( ! CreateProcess(programname,  //  _In_opt_     LPCTSTR lpApplicationName,
                                  NULL,         //  _Inout_opt_  LPTSTR lpCommandLine,
                                  NULL,         //  _In_opt_     LPSECURITY_ATTRIBUTES lpProcessAttributes,
                                  NULL,         //   _In_opt_     LPSECURITY_ATTRIBUTES lpThreadAttributes,
                                  FALSE,        //   _In_         BOOL bInheritHandles,
                                  NORMAL_PRIORITY_CLASS,  //  _In_         DWORD dwCreationFlags,
                                  NULL,         //  _In_opt_     LPVOID lpEnvironment,
                                  NULL,         //  _In_opt_     LPCTSTR lpCurrentDirectory,
                                  &startupinfo, //  _In_         LPSTARTUPINFO lpStartupInfo,
                                  &processinfo  //  _Out_        LPPROCESS_INFORMATION lpProcessInformation
                                  ))
                    {
                        fprintf(log,"[-] CreateProcess: %ld, error\n\tPROGRAM:%s\n",GetLastError(),programname);
                        error++;
                    }
                    else {
                        fprintf(log,"[+] CreateProcess: ok\n\tPROGRAM:%s\n",programname);
                    }
                }

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
                CloseHandle(&hToken);
            }
            //break;
        }
        /* Free the session info */
        WTSFreeMemory(&sessioninfo);
    }
    fprintf(log,"-- %s end --\n",argv[0]);
    /* Close the log file */
    fclose(log);
abort:
    return error;
}
