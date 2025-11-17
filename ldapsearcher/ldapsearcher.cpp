// ldapsearcher.cpp : This file contains the 'main' function. Program execution begins and ends there.
//


#define _WIN32_WINNT 0x0601  // Windows 7+ for ldap_initialize
#include <Windows.h>
#include <winldap.h>
#include <cassert>
#include <iostream>
#include <vector>
#include <array>
#include <string>


#pragma comment(lib, "wldap32.lib")

using namespace std;

array<wchar_t*, 11> vecAttributes = {
	const_cast<wchar_t*>(L"defaultNamingContext"),
	const_cast<wchar_t*>(L"configurationNamingContext"),
	const_cast<wchar_t*>(L"schemaNamingContext"),
	const_cast<wchar_t*>(L"rootDomainNamingContext"),
	const_cast<wchar_t*>(L"dnsHostName"),
	const_cast<wchar_t*>(L"supportedLDAPVersion"),
	const_cast<wchar_t*>(L"supportedSASLMechanisms"),
	const_cast<wchar_t*>(L"supportedControl"),
	const_cast<wchar_t*>(L"supportedCapabilities"),
	const_cast<wchar_t*>(L"supportedExtension"),
	nullptr  // We need a null array element for the ldap_search_sW call
};

void PrintLdapError(ULONG ldapErr, const wchar_t* where);
void PrintAttributeValue(LDAP* pLdapSession, LDAPMessage* ldapMessage, const wchar_t* attrName);

int main()
{
	LDAP* pLdapSessionHandle = nullptr;
	ULONG returnValue = 0;
	ULONG ldapVersion = LDAP_VERSION3;
	LDAPMessage* pLdapMessage = nullptr;
	LDAPMessage* pLdapMsgFirstEntry = nullptr;

	__try {

		pLdapSessionHandle = ldap_initW(nullptr, LDAP_PORT);

		if (!pLdapSessionHandle) {
			wcerr << L"Error: ldap_initW returned NULL";
			__leave;
		}

		returnValue = ldap_set_optionW(pLdapSessionHandle, LDAP_OPT_PROTOCOL_VERSION, &ldapVersion);
		if (LDAP_SUCCESS != returnValue) {
			PrintLdapError(returnValue, L"ldap_set_optionW");
			__leave;
		}

		returnValue = ldap_connect(pLdapSessionHandle, nullptr);
		if (LDAP_SUCCESS != returnValue) {
			PrintLdapError(returnValue, L"ldap_connect");
			__leave;
		}

		returnValue = ldap_bind_s(pLdapSessionHandle, nullptr, nullptr, LDAP_AUTH_NEGOTIATE);
		if (LDAP_SUCCESS != returnValue) {
			PrintLdapError(returnValue, L"ldap_bind_s");
			__leave;
		}

		returnValue = ldap_search_sW(pLdapSessionHandle,
			(PWCHAR)L"",
			LDAP_SCOPE_BASE,
			(PWCHAR)L"(objectClass=*)",
			const_cast<PWCHAR*>(vecAttributes.data()),
			0,
			&pLdapMessage);
		if (LDAP_SUCCESS != returnValue) {
			PrintLdapError(returnValue, L"ldap_search_sW(RootDSE)");
			if (pLdapMessage) {
				ldap_msgfree(pLdapMessage);
				pLdapMessage = nullptr;
			}
			__leave;
		}

		pLdapMsgFirstEntry = ldap_first_entry(pLdapSessionHandle, pLdapMessage);
		if (!pLdapMsgFirstEntry) {
			wcerr << L"No RootDSE entry returned\n";
			ldap_msgfree(pLdapMsgFirstEntry);
			__leave;
		}

		wcout << L"RootDSE attributes:\n";
		for (auto attr : vecAttributes) {
			PrintAttributeValue(pLdapSessionHandle, pLdapMessage, attr);
		}

		ldap_msgfree(pLdapMessage);

	}
	__finally {
		if (pLdapSessionHandle) {
			ldap_unbind(pLdapSessionHandle);
			pLdapSessionHandle = nullptr;
		}
	}

	return 0;
}

void PrintAttributeValue(LDAP* pLdapSession, LDAPMessage* ldapMessage, const wchar_t* attrName)
{
	if (!attrName) return;
	wchar_t** vals = ldap_get_valuesW(pLdapSession, ldapMessage, (PWCHAR)attrName);
	if (!vals) return;

	ULONG count = ldap_count_valuesW(vals);
	for (ULONG i = 0; i < count; ++i)
	{
		wcout << L"  " << attrName << L": "
			<< (vals[i] ? vals[i] : L"") << L"\n";
	}
	ldap_value_freeW(vals);
}



void PrintLdapError(ULONG ldapErr, const wchar_t* where)
{
	DWORD win32 = LdapMapErrorToWin32(ldapErr);
	wcerr << where << L" failed. LDAP=" << ldapErr
		<< L" (0x" << std::hex << ldapErr << std::dec << L")"
		<< L"  Win32=" << win32
		<< L" (0x" << std::hex << win32 << std::dec << L")\n";
}
