std::vector<SID_AND_ATTRIBUTES> ConvertToAttributes(const std::vector<SID> &sids, DWORD attributes) {
  std::vector<SID_AND_ATTRIBUTES> ret(sids.size());
  for (size_t i = 0; i < sids.size(); ++i) {
    ret[i].Attributes = attributes;
    ret[i].Sid = (PSID) & (sids[i]);
  }
  return ret;
}

bool DeletePrivilege(const HANDLE &token, const wchar_t *name) {
  TOKEN_PRIVILEGES privs = {};
  privs.PrivilegeCount = 1;
  if (!::LookupPrivilegeValue(nullptr, name, &privs.Privileges[0].Luid))
    return false;
  privs.Privileges[0].Attributes = SE_PRIVILEGE_REMOVED;
  return !!::AdjustTokenPrivileges(token, FALSE, &privs, 0, nullptr, nullptr);
}

PACL AddSidToDacl(const SID &sid, ACL *old_dacl, ACCESS_MODE access_mode, ACCESS_MASK access) {
  EXPLICIT_ACCESS new_access = {};
  new_access.grfAccessMode = access_mode;
  new_access.grfAccessPermissions = access;
  new_access.grfInheritance = NO_INHERITANCE;
  ::BuildTrusteeWithSid(&new_access.Trustee, (PSID)&sid);
  ACL *new_dacl = nullptr;
  if (ERROR_SUCCESS != ::SetEntriesInAcl(1, &new_access, old_dacl, &new_dacl))
    return nullptr;
  auto result = ::IsValidAcl(new_dacl);
  return new_dacl;
}

void AddSidToDefaultDacl(HANDLE token) 
{
  HANDLE query_token;
  auto result = ::DuplicateHandle(::GetCurrentProcess(), token, ::GetCurrentProcess(), &query_token, TOKEN_QUERY,FALSE, 0);

  DWORD size = 0;
  result = ::GetTokenInformation(query_token, TOKEN_INFORMATION_CLASS::TokenDefaultDacl, nullptr, 0, &size);
  auto buffer = malloc(size);
  memset(buffer, 0, size);
  result = ::GetTokenInformation(query_token, TOKEN_INFORMATION_CLASS::TokenDefaultDacl, buffer, size, &size);

  PTOKEN_DEFAULT_DACL default_dacl = (PTOKEN_DEFAULT_DACL)buffer;

  SID sid;
  DWORD sidSize;
  result = ::CreateWellKnownSid(WinRestrictedCodeSid, nullptr, &sid, &sidSize);
  PACL newDacl = AddSidToDacl(sid, default_dacl->DefaultDacl, ACCESS_MODE::GRANT_ACCESS, GENERIC_ALL);

  TOKEN_DEFAULT_DACL new_default_dacl = {0};
  new_default_dacl.DefaultDacl = newDacl;

  result = SetTokenInformation(token, TOKEN_INFORMATION_CLASS::TokenDefaultDacl, &new_default_dacl,
                               sizeof(new_default_dacl));
}

HANDLE GetRestrictedToken() {
  HANDLE tempToken;
  OpenProcessToken(::GetCurrentProcess(), TOKEN_ALL_ACCESS, &tempToken);

  std::vector<SID> sids_for_deny_only_;
  std::vector<SID_AND_ATTRIBUTES> deny_sids = ConvertToAttributes(sids_for_deny_only_, SE_GROUP_USE_FOR_DENY_ONLY);
  std::vector<SID> sids_to_restrict_;
  std::vector<SID_AND_ATTRIBUTES> restrict_sids = ConvertToAttributes(sids_to_restrict_, 0);

  bool result = true;
  HANDLE new_token_handle = nullptr;

  result = ::CreateRestrictedToken(tempToken, 0, static_cast<DWORD>(deny_sids.size()),
                                   deny_sids.data(), 0, nullptr, static_cast<DWORD>(restrict_sids.size()),
                                   restrict_sids.data(), &new_token_handle);

  //DeletePrivilege(new_token_handle, SE_CHANGE_NOTIFY_NAME);

  AddSidToDefaultDacl(new_token_handle);

  HANDLE finalToken;
  result =
      ::DuplicateHandle(::GetCurrentProcess(), new_token_handle, ::GetCurrentProcess(), &finalToken, TOKEN_ALL_ACCESS,
                        false, // Don't inherit.
                        0);

  return finalToken;
}

void _usages()
{
  auto token = GetRestrictedToken();
  auto result = CreateProcessAsUser(token, string_nullable(path), ea.data(), nullptr, nullptr, FALSE, createflags,
                      string_nullable(env), string_nullable(cwd), reinterpret_cast<STARTUPINFOW *>(&siex), &pi);
  /*auto result =
      CreateProcessWithTokenW(token,0,string_nullable(path), ea.data(), createflags,
                          string_nullable(env), string_nullable(cwd), reinterpret_cast<STARTUPINFOW *>(&siex), &pi);*/
  if (!result) {
    ec = bela::make_system_error_code(L"appcommand::execute<CreateProcessW> ");
    return false;
  }
}
