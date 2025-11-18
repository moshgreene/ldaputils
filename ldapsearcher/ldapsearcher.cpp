// ldapsearcher.cpp : This file contains the 'main' function. Program execution begins and ends there.
//


#include "framework.h"

using namespace std;

array<wchar_t*, 4> vecAttributes = {
	const_cast<wchar_t*>(L"cn"),
	const_cast<wchar_t*>(L"title"),
	const_cast<wchar_t*>(L"distinguishedName"),
	nullptr  // We need a null array element for the ldap_search_sW call
};

int wmain(int argc, wchar_t* argv[])
{
	if (argc > 2) {
		wcerr << L"supply a SAM account name\n";
		return 0;
	}

	wstring samAccountName{ argv[1] };
	wstring ldapSearch{ L"(&(objectClass=person)(sAMAccountName=" + samAccountName + L"))" };

	LDAP* pLdapSessionHandle = nullptr;
	ULONG returnValue = 0;
	ULONG ldapVersion = LDAP_VERSION3;
	LDAPMessage* pLdapMessage = nullptr;
	LDAPMessage* pLdapMsgFirstEntry = nullptr;
	wstring rootDSE;

	pLdapSessionHandle = ldap_initW(nullptr, LDAP_PORT);
	if (!pLdapSessionHandle) {
		wcerr << L"Error: ldap_initW returned NULL";
		goto Cleanup;
	}

	returnValue = ldap_set_optionW(pLdapSessionHandle, LDAP_OPT_PROTOCOL_VERSION, &ldapVersion);
	if (LDAP_SUCCESS != returnValue) {
		PrintLdapError(returnValue, L"ldap_set_optionW");
		goto Cleanup;
	}

	returnValue = ldap_connect(pLdapSessionHandle, nullptr);
	if (LDAP_SUCCESS != returnValue) {
		PrintLdapError(returnValue, L"ldap_connect");
		goto Cleanup;
	}

	returnValue = ldap_bind_s(pLdapSessionHandle, nullptr, nullptr, LDAP_AUTH_NEGOTIATE);
	if (LDAP_SUCCESS != returnValue) {
		PrintLdapError(returnValue, L"ldap_bind_s");
		goto Cleanup;
	}

	GetRootDSE(pLdapSessionHandle, rootDSE);

	returnValue = ldap_search_sW(
		pLdapSessionHandle,
		(PWCHAR)rootDSE.c_str(),
		LDAP_SCOPE_SUBTREE,
		(PWCHAR)ldapSearch.c_str(),
		const_cast<PWCHAR*>(vecAttributes.data()),
		0,
		&pLdapMessage);
	if (LDAP_SUCCESS == returnValue) {
		PrintAttributeValue(pLdapSessionHandle, pLdapMessage, L"distinguishedName");
	}
	else
	{
		PrintLdapError(returnValue, L"ldap_search_sW(RootDSE)");
		if (pLdapMessage) {
			ldap_msgfree(pLdapMessage);
			pLdapMessage = nullptr;
		}
		goto Cleanup;;
	}

	pLdapMsgFirstEntry = ldap_first_entry(pLdapSessionHandle, pLdapMessage);
	if (!pLdapMsgFirstEntry) {
		wcerr << L"No RootDSE entry returned\n";
		ldap_msgfree(pLdapMsgFirstEntry);
		goto Cleanup;;
	}

	wcout << L"RootDSE attributes:\n";
	for (auto attr : vecAttributes) {
		PrintAttributeValue(pLdapSessionHandle, pLdapMessage, attr);
	}

	ldap_msgfree(pLdapMessage);


Cleanup:
	if (pLdapSessionHandle) {
		ldap_unbind(pLdapSessionHandle);
		pLdapSessionHandle = nullptr;
	}


	return 0;
}

void PrintAttributeValue(LDAP* pLdapSession, LDAPMessage* ldapMessage, const wchar_t* attrName)
{
	if (!attrName) { return; }
	wchar_t** vals = ldap_get_valuesW(pLdapSession, ldapMessage, (PWCHAR)attrName);
	if (!vals) { return; }

	ULONG count = ldap_count_valuesW(vals);
	for (ULONG i = 0; i < count; ++i)
	{
		std::wcout << L"  " << attrName << L": "
			<< (vals[i] ? vals[i] : L"") << L"\n";
	}
	ldap_value_freeW(vals);
}

void PrintLdapError(ULONG ldapErr, const wchar_t* where)
{
	DWORD win32 = LdapMapErrorToWin32(ldapErr);
	std::wcerr << where << L" failed. LDAP=" << ldapErr
		<< L" (0x" << std::hex << ldapErr << std::dec << L")"
		<< L"  Win32=" << win32
		<< L" (0x" << std::hex << win32 << std::dec << L")\n";
}
