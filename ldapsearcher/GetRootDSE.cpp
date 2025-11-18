// ldapsearcher.cpp : This file contains the 'main' function. Program execution begins and ends there.
//


#include "framework.h"

void GetRootDSE(LDAP* pLdapSessionHandle, std::wstring& rootDSE)
{
	ULONG returnValue = 0;
	LDAPMessage* pLdapMessage = nullptr;
	LDAPMessage* pLdapMsgFirstEntry = nullptr;

	const PWSTR attrs[] = { (PWSTR)L"defaultNamingContext", nullptr };

	returnValue = ldap_search_sW(pLdapSessionHandle,
		(PWCHAR)L"",
		LDAP_SCOPE_BASE,
		(PWCHAR)L"(objectClass=*)",
		const_cast<PWCHAR*>(attrs),
		0,
		&pLdapMessage);
	if (LDAP_SUCCESS != returnValue) {
		PrintLdapError(returnValue, L"ldap_search_sW(RootDSE)");
		if (pLdapMessage) {
			ldap_msgfree(pLdapMessage);
			pLdapMessage = nullptr;
		}
		rootDSE.assign(L"");
	}

	pLdapMsgFirstEntry = ldap_first_entry(pLdapSessionHandle, pLdapMessage);
	if (!pLdapMsgFirstEntry) {
		std::wcerr << L"No RootDSE entry returned\n";
		ldap_msgfree(pLdapMsgFirstEntry);
		rootDSE = L"";
	}

	std::wcout << L"RootDSE attributes:\n";
	bool bRootDSEFound = false;
	if (LDAP_SUCCESS == returnValue) {
		for (auto attr : attrs) {
			wchar_t** vals = ldap_get_valuesW(pLdapSessionHandle, pLdapMsgFirstEntry, (PWCHAR)attr);
			if (*vals) { 
				rootDSE.assign(*vals);
				bRootDSEFound = true;
				ldap_value_freeW(vals);
				break;
			}
			else {
				return;
			}
		}
	}
	else
	{
		PrintLdapError(returnValue, L"ldap_search_sW(RootDSE)");
		if (pLdapMessage) {
			ldap_msgfree(pLdapMessage);
			pLdapMessage = nullptr;
		}
	}

	if (pLdapMessage) {
		ldap_msgfree(pLdapMessage);
		pLdapMessage = nullptr;
	}

	return;
}
