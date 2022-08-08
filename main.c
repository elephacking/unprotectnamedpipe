#include "windows.h"
#include "stdio.h"
#include "aclapi.h"
#include "accctrl.h"
#include "sddl.h"

char* PIPENAME = "\\\\.\\pipe\\MyPipeName";

void main() {
	PSECURITY_DESCRIPTOR sd;
	PACL old_dacl, new_dacl;
	
	DWORD flags = PIPE_ACCESS_DUPLEX | WRITE_DAC | FILE_FLAG_OVERLAPPED;
	PSID everyone, anonymous;

	ConvertStringSidToSid(TEXT("S-1-1-0"), &everyone);
	ConvertStringSidToSid(TEXT("S-1-5-7"), &anonymous);
	
	EXPLICIT_ACCESS ea[2];
	ea[0].grfAccessPermissions = FILE_GENERIC_WRITE;
	ea[0].grfAccessMode = GRANT_ACCESS;
	ea[0].grfInheritance = NO_INHERITANCE;
	ea[0].Trustee.pMultipleTrustee = NULL;
	ea[0].Trustee.MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE;
	ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
	ea[0].Trustee.TrusteeType = TRUSTEE_IS_UNKNOWN;
	ea[0].Trustee.ptstrName = (LPTSTR) everyone;

	ea[1].grfAccessPermissions = 0;
	ea[1].grfAccessMode = REVOKE_ACCESS;
	ea[1].grfInheritance = NO_INHERITANCE;
	ea[1].Trustee.pMultipleTrustee = NULL;
	ea[1].Trustee.MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE;
	ea[1].Trustee.TrusteeForm = TRUSTEE_IS_SID;
	ea[1].Trustee.TrusteeType = TRUSTEE_IS_UNKNOWN;
	ea[1].Trustee.ptstrName = (LPTSTR) anonymous;

	flags |= FILE_FLAG_FIRST_PIPE_INSTANCE;
	
	HANDLE pipe = CreateFileA(PIPENAME, FILE_ALL_ACCESS, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (pipe == INVALID_HANDLE_VALUE) {
		printf("Could not open the pipe\n");
		return;
	}
	
	//getchar();
	if (GetSecurityInfo(pipe, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION,
                        NULL, NULL, &old_dacl, NULL, &sd) != ERROR_SUCCESS)
    {
        CloseHandle(pipe);
        printf("Could not get pipe security info\n");
		return;
    }

    if (SetEntriesInAcl(2, ea, old_dacl, &new_dacl) != ERROR_SUCCESS)
    {
        printf("Could not set entries in new acl\n");
        CloseHandle(pipe);
		return;
    }

    if (SetSecurityInfo(pipe, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION,
                        NULL, NULL, new_dacl, NULL) != ERROR_SUCCESS)
    {
        printf("Could not set pipe security info\n");
        CloseHandle(pipe);
		return;
    }
	CloseHandle(pipe);
	printf("Done\n");
	return;
}