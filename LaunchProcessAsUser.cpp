bool LaunchProcessAsUser(tstring_view applicationName, tstring_view cmd)
{
    HANDLE tokenHandle;
    HANDLE duplicatedTokenHandle;
    DWORD errorCode;
    bool re = false;

    if (!applicationName.data())
        return re;
    
    re = WTSQueryUserToken(GetCurrentSessionID(), &tokenHandle);
    if (!re)
        return false;

    SECURITY_ATTRIBUTES sa;
    memset(&sa, 0, sizeof(SECURITY_ATTRIBUTES));
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);

    re = DuplicateTokenEx(tokenHandle, MAXIMUM_ALLOWED, &sa, SECURITY_IMPERSONATION_LEVEL::SecurityIdentification, TokenPrimary, &duplicatedTokenHandle);
    if (!re)
    {
        CloseHandle(tokenHandle);
        return false;
    }
        
    STARTUPINFO si;
    PROCESS_INFORMATION pi;

    ZeroMemory(&si, sizeof(STARTUPINFO));
    si.cb = sizeof(STARTUPINFO);
    si.lpDesktop = (WCHAR*)L"winsta0\\default";

    re = CreateProcessAsUser(duplicatedTokenHandle, applicationName.data(), (LPWSTR)cmd.data(), &sa, &sa, false, NORMAL_PRIORITY_CLASS, NULL, NULL, &si, &pi);
    errorCode = GetLastError();

    CloseHandle(tokenHandle);
    CloseHandle(duplicatedTokenHandle);
    return re;
}
