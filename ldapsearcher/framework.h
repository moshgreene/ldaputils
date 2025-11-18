#pragma once
#define _WIN32_WINNT 0x0601  // Windows 7+ for ldap_initialize
#include <Windows.h>
#include <winldap.h>
#include <cassert>
#include <iostream>
#include <vector>
#include <array>
#include <string>
#include "GetRootDSE.h"


#pragma comment(lib, "wldap32.lib")


void PrintLdapError(ULONG ldapErr, const wchar_t* where);
void PrintAttributeValue(LDAP* pLdapSession, LDAPMessage* ldapMessage, const wchar_t* attrName);