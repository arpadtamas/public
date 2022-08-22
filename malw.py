import pefile, ssdeep, psycopg2, re, sys
from datetime import datetime
from filehash import FileHash

connection = psycopg2.connect(user="postgres",
                              password="pwd",
                              host="127.0.0.1",
                              port="5432",
                              database="malw_db")
cursor = connection.cursor()


#CREATE DATABASE malw_db;
#create table sections (file_sha512 varchar(128), name varchar(255), section_md5 varchar(32), section_sha1 varchar(40), section_sha256 varchar(64), section_sha512 varchar(128)); 
#create table malware(id serial PRIMARY KEY, time varchar(40), imphash varchar(32), file_md5 varchar(32), file_sha1 varchar(40), file_sha256 varchar(64), file_sha512 varchar(128), ssdeep varchar(255), section_num int); 

file = sys.argv[1]
malware = pefile.PE(file)

time = malware.FILE_HEADER.TimeDateStamp
imphash = malware.get_imphash()
file_md5 = FileHash("md5").hash_file(file)
file_sha1 = FileHash("sha1").hash_file(file)
file_sha256 = FileHash("sha256").hash_file(file)
file_sha512 = FileHash("sha512").hash_file(file)
ssdeep_hash = ssdeep.hash_from_file(file)
section_num = int(malware.FILE_HEADER.NumberOfSections)


print("File name: ", file)
print("Compilation timestamp: ", datetime.fromtimestamp(time))
print("MD5: ", file_md5)
print("sha1: ", file_sha1)
print("sha256: ", file_sha256)
print("sha512: ", file_sha512)
print("Imphash: ", imphash)
print("Ssdeep: ", ssdeep_hash)

cursor.execute("SELECT * FROM malware WHERE imphash = %s OR file_md5 = %s OR file_sha1 = %s OR file_sha256 = %s OR file_sha512 = %s", (imphash, file_md5, file_sha1, file_sha256, file_sha512,))
result_set = cursor.fetchall()
print("-----------\nFound", len(result_set),"matches: ")
for row in result_set:
    print(row[5])
    
print("-----------\nssdeep compare:")
cursor.execute("SELECT ssdeep, file_sha256 FROM malware")
result_set = cursor.fetchall()
for row in result_set:
	percentage = ssdeep.compare(ssdeep_hash, row[0])
	if (percentage) > 0:
		print(percentage, "% match with", row[1])
    
    
cursor.execute('INSERT INTO malware (time, imphash, file_md5, file_sha1, file_sha256, file_sha512, ssdeep, section_num) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)', (time, imphash, file_md5, file_sha1, file_sha256, file_sha512, ssdeep_hash, section_num))
connection.commit()


print("-----------\nNumberOfSections: ", section_num)

for x in range(0, section_num):
	name = malware.sections[x].Name.decode(errors='replace',).rstrip('\x00')
	section_md5 = malware.sections[x].get_hash_md5()
	section_sha1 = malware.sections[x].get_hash_sha1()
	section_sha256 = malware.sections[x].get_hash_sha256()
	section_sha512 = malware.sections[x].get_hash_sha512()
	print("-----------\nSection name:", name)
	print("\tEntropy (Min=0.0, Max=8.0):", malware.sections[x].get_entropy())
	print("\tMD5 hash: ", section_md5)
	print("\tSHA1 hash: ", section_sha1)
	print("\tSHA256 hash: ", section_sha256)
	print("\tSHA512 hash: ", section_sha512)
	print("\tVirtual size: ", malware.sections[x].Misc_VirtualSize)
	print("\tSizeOfRawData: ", malware.sections[x].SizeOfRawData)
	print("\tFlags: ", malware.sections[x].Characteristics)
	cursor.execute("SELECT file_sha256, name FROM sections WHERE section_md5 = %s OR section_sha1 = %s OR section_sha256 = %s OR section_sha512 = %s", (section_md5, section_sha1, section_sha256, section_sha512,))
	result_set = cursor.fetchall()
	print("\tFound", len(result_set)," matches: ")
	for row in result_set:
	    print("\t\tSection", row[1], "matches in", row[0])
	cursor.execute('INSERT INTO sections (file_sha256, name, section_md5, section_sha1, section_sha256, section_sha512) VALUES (%s, %s, %s, %s, %s, %s)', (file_sha256, name, section_md5, section_sha1, section_sha256, section_sha256))
	connection.commit()


apis = []
for entry in malware.DIRECTORY_ENTRY_IMPORT:
	for imp in entry.imports:
		if imp.name is not None:
			imps = re.findall(r"'([^']*)'", str(imp.name))
			apis.append(imps[0])

		
crypt = ["CryptAcquireContextA", "EncryptFileA", "CryptEncrypt", "CryptDecrypt", "CryptCreateHash", "CryptHashData", "CryptDeriveKey", "CryptSetKeyParam", "CryptGetHashParam", "CryptSetKeyParam", "CryptDestroyKey", "CryptGenRandom", "DecryptFileA", "FlushEfsCache", "GetLogicalDrives", "GetDriveTypeA", "CryptStringToBinary", "CryptBinaryToString", "CryptReleaseContext", "CryptDestroyHash", "EnumSystemLocalesA"]
enum = ["CreateToolhelp32Snapshot", "EnumDeviceDrivers", "EnumProcesses", "EnumProcessModules", "EnumProcessModulesEx", "FindFirstFileA", "FindNextFileA", "GetLogicalProcessorInformation", "GetLogicalProcessorInformationEx", "GetModuleBaseNameA", "GetSystemDefaultLangId", "GetVersionExA", "GetWindowsDirectoryA", "IsWoW64Process", "Module32First", "Module32Next", "Process32First", "Process32Next", "ReadProcessMemory", "Thread32First", "Thread32Next", "GetSystemDirectoryA", "GetSystemTime", "ReadFile", "GetComputerNameA", "VirtualQueryEx", "GetProcessIdOfThread", "GetProcessId", "GetCurrentThread", "GetCurrentThreadId", "GetThreadId", "GetThreadInformation", "GetCurrentProcess", "GetCurrentProcessId", "SearchPathA", "GetFileTime", "GetFileAttributesA", "LookupPrivilegeValueA", "LookupAccountNameA", "GetCurrentHwProfileA", "GetUserNameA", "RegEnumKeyExA", "RegEnumValueA", "RegQueryInfoKeyA", "RegQueryMultipleValuesA", "RegQueryValueExA", "NtQueryDirectoryFile", "NtQueryInformationProcess", "NtQuerySystemEnvironmentValueEx", "EnumDesktopWindows", "EnumWindows", "NetShareEnum", "NetShareGetInfo", "NetShareCheck", "GetAdaptersInfo", "PathFileExistsA", "GetNativeSystemInfo", "RtlGetVersion", "GetIpNetTable", "GetLogicalDrives", "GetDriveTypeA", "RegEnumKeyA", "WNetEnumResourceA", "WNetCloseEnum", "FindFirstUrlCacheEntryA", "FindNextUrlCacheEntryA", "WNetAddConnection2A", "WNetAddConnectionA", "EnumResourceTypesA", "EnumResourceTypesExA", "GetSystemTimeAsFileTime", "GetThreadLocale", "EnumSystemLocalesA2"]
inj = ["CreateFileMappingA" "CreateProcessA", "CreateRemoteThread", "CreateRemoteThreadEx", "GetModuleHandleA", "GetProcAddress", "GetThreadContext", "HeapCreate", "LoadLibraryA", "LoadLibraryExA", "LocalAlloc", "MapViewOfFile", "MapViewOfFile2", "MapViewOfFile3", "MapViewOfFileEx", "OpenThread", "Process32First", "Process32Next", "QueueUserAPC", "ReadProcessMemory", "ResumeThread", "SetProcessDEPPolicy", "SetThreadContext", "SuspendThread", "Thread32First", "Thread32Next", "Toolhelp32ReadProcessMemory", "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx", "WriteProcessMemory", "VirtualAllocExNuma", "VirtualAlloc2", "VirtualAlloc2FromApp", "VirtualAllocFromApp", "VirtualProtectFromApp", "CreateThread", "WaitForSingleObject", "OpenProcess", "OpenFileMappingA", "GetProcessHeap", "GetProcessHeaps", "HeapAlloc", "HeapReAlloc", "GlobalAlloc", "AdjustTokenPrivileges", "CreateProcessAsUserA", "OpenProcessToken", "CreateProcessWithTokenW", "NtAdjustPrivilegesToken", "NtAllocateVirtualMemory", "NtContinue", "NtCreateProcess", "NtCreateProcessEx", "NtCreateSection", "NtCreateThread", "NtCreateThreadEx", "NtCreateUserProcess", "NtDuplicateObject", "NtMapViewOfSection", "NtOpenProcess", "NtOpenThread", "NtProtectVirtualMemory", "NtQueueApcThread", "NtQueueApcThreadEx", "NtQueueApcThreadEx2", "NtReadVirtualMemory", "NtResumeThread", "NtUnmapViewOfSection", "NtWaitForMultipleObjects", "NtWaitForSingleObject", "NtWriteVirtualMemory", "RtlCreateHeap", "LdrLoadDll", "RtlMoveMemory", "RtlCopyMemory", "SetPropA", "WaitForSingleObjectEx", "WaitForMultipleObjects", "WaitForMultipleObjectsEx", "KeInsertQueueApc", "Wow64SetThreadContext", "NtSuspendProcess", "NtResumeProcess", "DuplicateToken", "NtReadVirtualMemoryEx", "CreateProcessInternal", "EnumSystemLocalesA", "UuidFromStringA"]
eva = ["CreateFileMappingA", "DeleteFileA", "GetModuleHandleA", "GetProcAddress", "LoadLibraryA", "LoadLibraryExA", "LoadResource", "SetEnvironmentVariableA", "SetFileTime", "Sleep", "WaitForSingleObject", "SetFileAttributesA", "SleepEx", "NtDelayExecution", "NtWaitForMultipleObjects", "NtWaitForSingleObject", "CreateWindowExA", "RegisterHotKey", "timeSetEvent", "IcmpSendEcho", "WaitForSingleObjectEx", "WaitForMultipleObjects", "WaitForMultipleObjectsEx", "SetWaitableTimer", "CreateTimerQueueTimer", "CreateWaitableTimer", "SetWaitableTimer", "SetTimer", "Select", "ImpersonateLoggedOnUser", "SetThreadToken", "DuplicateToken", "SizeOfResource", "LockResource", "CreateProcessInternal", "TimeGetTime", "EnumSystemLocalesA", "UuidFromStringA"]
spy = ["AttachThreadInput", "CallNextHookEx", "GetAsyncKeyState", "GetClipboardData", "GetDC", "GetDCEx", "GetForegroundWindow", "GetKeyboardState", "GetKeyState", "GetMessageA", "GetRawInputData", "GetWindowDC", "MapVirtualKeyA", "MapVirtualKeyExA", "PeekMessageA", "PostMessageA", "PostThreadMessageA", "RegisterHotKey", "RegisterRawInputDevices", "SendMessageA", "SendMessageCallbackA", "SendMessageTimeoutA", "SendNotifyMessageA", "SetWindowsHookExA", "SetWinEventHook", "UnhookWindowsHookEx", "BitBlt", "StretchBlt", "GetKeynameTextA"]
net = ["WinExec", "FtpPutFileA", "HttpOpenRequestA", "HttpSendRequestA", "HttpSendRequestExA", "InternetCloseHandle", "InternetOpenA", "InternetOpenUrlA", "InternetReadFile", "InternetReadFileExA", "InternetWriteFile", "URLDownloadToFile", "URLDownloadToCacheFile", "URLOpenBlockingStream", "URLOpenStream", "Accept", "Bind", "Connect", "Gethostbyname", "Inet_addr", "Recv", "Send", "WSAStartup", "Gethostname", "Socket", "WSACleanup", "Listen", "ShellExecuteA", "ShellExecuteExA", "DnsQuery_A", "DnsQueryEx", "WNetOpenEnumA", "FindFirstUrlCacheEntryA", "FindNextUrlCacheEntryA", "InternetConnectA", "InternetSetOptionA", "WSASocketA", "Closesocket", "WSAIoctl", "ioctlsocket", "HttpAddRequestHeaders"]
anti = ["CreateToolhelp32Snapshot", "GetLogicalProcessorInformation", "GetLogicalProcessorInformationEx", "GetTickCount", "OutputDebugStringA", "CheckRemoteDebuggerPresent", "Sleep", "GetSystemTime", "GetComputerNameA", "SleepEx", "IsDebuggerPresent", "GetUserNameA", "NtQueryInformationProcess", "ExitWindowsEx", "FindWindowA", "FindWindowExA", "GetForegroundWindow", "GetTickCount64", "QueryPerformanceFrequency", "QueryPerformanceCounter", "GetNativeSystemInfo", "RtlGetVersion", "GetSystemTimeAsFileTime", "CountClipboardFormats"]
etc = ["ConnectNamedPipe", "CopyFileA", "CreateFileA", "CreateMutexA", "CreateMutexExA", "DeviceIoControl", "FindResourceA", "FindResourceExA", "GetModuleBaseNameA", "GetModuleFileNameA", "GetModuleFileNameExA", "GetTempPathA", "IsWoW64Process", "MoveFileA", "MoveFileExA", "PeekNamedPipe", "WriteFile", "TerminateThread", "CopyFile2", "CopyFileExA", "CreateFile2", "GetTempFileNameA", "TerminateProcess", "SetCurrentDirectory", "FindClose", "SetThreadPriority", "UnmapViewOfFile", "ControlService", "ControlServiceExA", "CreateServiceA", "DeleteService", "OpenSCManagerA", "OpenServiceA", "RegOpenKeyA", "RegOpenKeyExA", "StartServiceA", "StartServiceCtrlDispatcherA", "RegCreateKeyExA", "RegCreateKeyA", "RegSetValueExA", "RegSetKeyValueA", "RegDeleteValueA", "RegOpenKeyExA", "RegEnumKeyExA", "RegEnumValueA", "RegGetValueA", "RegFlushKey", "RegGetKeySecurity", "RegLoadKeyA", "RegLoadMUIStringA", "RegOpenCurrentUser", "RegOpenKeyTransactedA", "RegOpenUserClassesRoot", "RegOverridePredefKey", "RegReplaceKeyA", "RegRestoreKeyA", "RegSaveKeyA", "RegSaveKeyExA", "RegSetKeySecurity", "RegUnLoadKeyA", "RegConnectRegistryA", "RegCopyTreeA", "RegCreateKeyTransactedA", "RegDeleteKeyA", "RegDeleteKeyExA", "RegDeleteKeyTransactedA", "RegDeleteKeyValueA", "RegDeleteTreeA", "RegDeleteValueA", "RegCloseKey", "NtClose", "NtCreateFile", "NtDeleteKey", "NtDeleteValueKey", "NtMakeTemporaryObject", "NtSetContextThread", "NtSetInformationProcess", "NtSetInformationThread", "NtSetSystemEnvironmentValueEx", "NtSetValueKey", "NtShutdownSystem", "NtTerminateProcess", "NtTerminateThread", "RtlSetProcessIsCritical", "DrawTextExA", "GetDesktopWindow", "SetClipboardData", "SetWindowLongA", "SetWindowLongPtrA", "OpenClipboard", "SetForegroundWindow", "BringWindowToTop", "SetFocus", "ShowWindow", "NetShareSetInfo", "NetShareAdd", "NtQueryTimer", "GetIpNetTable", "GetLogicalDrives", "GetDriveTypeA", "CreatePipe", "RegEnumKeyA", "WNetOpenEnumA", "WNetEnumResourceA", "WNetAddConnection2A", "CallWindowProcA", "NtResumeProcess", "lstrcatA", "ImpersonateLoggedOnUser", "SetThreadToken", "SizeOfResource", "LockResource", "UuidFromStringA"]

ransomware = set(apis).intersection(crypt)
enumeration = set(apis).intersection(enum)
injection = set(apis).intersection(inj)
evasion = set(apis).intersection(eva)
spying = set(apis).intersection(spy)
internet = set(apis).intersection(net)
antidebug = set(apis).intersection(anti)
other = set(apis).intersection(etc)
print("-----------\nSuspicious WinAPIs:\n")
if len(ransomware) > 0:
	print("Cryptographic functions:")
	for i in ransomware:
		print("\t", i)
if len(enumeration) > 0:
	print("System enumeration:")
	for i in enumeration:
		print("\t", i)
if len(injection) > 0:
	print("Process related attacks:")
	for i in injection:
		print("\t", i)
if len(evasion) > 0:
	print("Evasive behaviour:")
	for i in evasion:
		print("\t", i)
if len(spying) > 0:
	print("Spying on user action:")
	for i in spying:
		print("\t", i)
if len(internet) > 0:
	print("Internet connectivity:")
	for i in internet:
		print("\t", i)
if len(spying) > 0:
	print("Anti-debugging functions:")
	for i in spying:
		print("\t", i)
if len(other) > 0:
	print("Other malware functions:")
	for i in other:
		print("\t", i)



"""

EXAMPLE RESULT

File name:  /home/dev/Desktop/emotet2.exe
Compilation timestamp:  2022-07-01 13:47:26
MD5:  e56b34b4f506e8607a1d9d0fe22dec34
sha1:  f560733a1361162911f902034b19d7b414703ffe
sha256:  791c0f3e7e6d9c570ad29269ec3bc3f78fadc3c1952f35eb7ac694f3e31551aa
sha512:  cfae265178c94396b43a2f07753a6ce87851986781259c3b12b4051e4057e3b9ba034f30f22153551f37af1e4fd74e1948e24340e7d8200219407294a6f6e4b9
Imphash:  311fcea8519089f91be16d46a87cbd88
Ssdeep:  12288:QolWKutg7C7t1DtuANCqKLvr+U4rG2a/FviAzPVC5Go3DHeFP8ge/wgS0yXD:QolJut3nCqWB5ztqL6x
-----------
Found 3 matches: 
791c0f3e7e6d9c570ad29269ec3bc3f78fadc3c1952f35eb7ac694f3e31551aa
791c0f3e7e6d9c570ad29269ec3bc3f78fadc3c1952f35eb7ac694f3e31551aa
258bb2b23c6ea7434eb8c965a168e7eb87257f5d3e4c4272c5ab29e873d6fbd3
-----------
ssdeep compare:
100 % match with 791c0f3e7e6d9c570ad29269ec3bc3f78fadc3c1952f35eb7ac694f3e31551aa
100 % match with 791c0f3e7e6d9c570ad29269ec3bc3f78fadc3c1952f35eb7ac694f3e31551aa
99 % match with 258bb2b23c6ea7434eb8c965a168e7eb87257f5d3e4c4272c5ab29e873d6fbd3
-----------
NumberOfSections:  6
-----------
Section name: .text
	Entropy (Min=0.0, Max=8.0): 6.44235674698389
	MD5 hash:  cef6e1d01ba2bb6b3398e1569f2d9e71
	SHA1 hash:  008c9593118af992c4e5bccf3850876d8ffee396
	SHA256 hash:  8eed84c3d665fbd725baac9197e5aeb07709f7962366ba0fa719aa7176347ec4
	SHA512 hash:  c950d476c1d83a5ad4b9b9e9f2c9c67d80846cd34e94b21f81b1d0d234a4daa58ad1f1b6e2832f74fe793a79b5b722f24d0efcdb3315589a2ec9f783b533150c
	Virtual size:  148238
	SizeOfRawData:  148480
	Flags:  1610612768
	Found 3  matches: 
		Section .text matches in 791c0f3e7e6d9c570ad29269ec3bc3f78fadc3c1952f35eb7ac694f3e31551aa
		Section .text matches in 791c0f3e7e6d9c570ad29269ec3bc3f78fadc3c1952f35eb7ac694f3e31551aa
		Section .text matches in 258bb2b23c6ea7434eb8c965a168e7eb87257f5d3e4c4272c5ab29e873d6fbd3
-----------
Section name: .rdata
	Entropy (Min=0.0, Max=8.0): 4.59376534829807
	MD5 hash:  132b89ae972e5be04cf4952746188456
	SHA1 hash:  0297d8bc0db6da412df23b7f29a485a64a9c3c9e
	SHA256 hash:  8f5a4c99509167166a05cdee60d7af115f81a3a373e5b05ee80ab4c86e621516
	SHA512 hash:  e5150847ee863578cc8f540736245579882af269c7e1d476fdf67bc7249df4d0513af0b8d96ac429732c7ff1fa93418ef1979f359c3a0853069f0a40370da9e9
	Virtual size:  42962
	SizeOfRawData:  43008
	Flags:  1073741888
	Found 2  matches: 
		Section .rdata matches in 791c0f3e7e6d9c570ad29269ec3bc3f78fadc3c1952f35eb7ac694f3e31551aa
		Section .rdata matches in 791c0f3e7e6d9c570ad29269ec3bc3f78fadc3c1952f35eb7ac694f3e31551aa
-----------
Section name: .data
	Entropy (Min=0.0, Max=8.0): 3.502583975677695
	MD5 hash:  4ef0e1e3e0bfe5ca04b01ac006835166
	SHA1 hash:  dcf92fe25c8de4b48f8c288c59fc0f4c2908dc82
	SHA256 hash:  5133dba5c6203cc136aee4ba0944bc8eff5cbee512b4f96ecf7b5d368389f30d
	SHA512 hash:  1b41ea18e3de8936e729180720115555322f28866876fb7fbf16425fe6f4a5f5eb298d4d6e1d72cb99add486a41efa294abbedbe734d15e31aa72f4ce3b32be4
	Virtual size:  19492
	SizeOfRawData:  9216
	Flags:  3221225536
	Found 3  matches: 
		Section .data matches in 791c0f3e7e6d9c570ad29269ec3bc3f78fadc3c1952f35eb7ac694f3e31551aa
		Section .data matches in 791c0f3e7e6d9c570ad29269ec3bc3f78fadc3c1952f35eb7ac694f3e31551aa
		Section .data matches in 258bb2b23c6ea7434eb8c965a168e7eb87257f5d3e4c4272c5ab29e873d6fbd3
-----------
Section name: .pdata
	Entropy (Min=0.0, Max=8.0): 5.17276425766517
	MD5 hash:  980b4ee87837daf081d2d6a0f888a29c
	SHA1 hash:  7574e910cdac3fbd46bbfda1e8a166edd016e667
	SHA256 hash:  768da0771a681c4159d3cbc084873864840a5d786b724254d65a5efb9d241e12
	SHA512 hash:  4e1edcf6b156d97f4a7219a4061074772797876225f995d8d6f38e22de049ff01aac335695bb09f4f588a4b5fe1f48893f909826fe583279cbd7b82b389cf9c5
	Virtual size:  7404
	SizeOfRawData:  7680
	Flags:  1073741888
	Found 3  matches: 
		Section .pdata matches in 791c0f3e7e6d9c570ad29269ec3bc3f78fadc3c1952f35eb7ac694f3e31551aa
		Section .pdata matches in 791c0f3e7e6d9c570ad29269ec3bc3f78fadc3c1952f35eb7ac694f3e31551aa
		Section .pdata matches in 258bb2b23c6ea7434eb8c965a168e7eb87257f5d3e4c4272c5ab29e873d6fbd3
-----------
Section name: .rsrc
	Entropy (Min=0.0, Max=8.0): 7.924545690560659
	MD5 hash:  3c7589095e092441151889a6a17aa4f8
	SHA1 hash:  d6e19244a66c6a16fafabdffcf317819a8ee242f
	SHA256 hash:  3703ab7e6f7646fac074a3de2fb0cc4efcdb2a29c3dd5c0e34ae0c7d7205110e
	SHA512 hash:  bbb06a2d6813d8168c1701dfde3879ee9b7b171c7868f30bc4a5d70cad5ec676cf3990ef629b5c255c3a0d461b489b32296f14cf683210661d4da9d451e72f4f
	Virtual size:  538108
	SizeOfRawData:  538112
	Flags:  1073741888
	Found 3  matches: 
		Section .rsrc matches in 791c0f3e7e6d9c570ad29269ec3bc3f78fadc3c1952f35eb7ac694f3e31551aa
		Section .rsrc matches in 791c0f3e7e6d9c570ad29269ec3bc3f78fadc3c1952f35eb7ac694f3e31551aa
		Section .rsrc matches in 258bb2b23c6ea7434eb8c965a168e7eb87257f5d3e4c4272c5ab29e873d6fbd3
-----------
Section name: .reloc
	Entropy (Min=0.0, Max=8.0): 3.0740959788330127
	MD5 hash:  8265cb79bd9c479f27dd85010440d841
	SHA1 hash:  552a0b20a7fe1c78ea7c0276c831686f41baa9ee
	SHA256 hash:  d4bc750b1ac9130bd4c360fdf51ae5efc51f3b0b921fe4dcf01765ddda7949b6
	SHA512 hash:  44fe7a48a03b4e4c6bb771a7163259ed855f3dc05358feed5518b3eb3bf7d16158aa36ea66a26f45cc33a9f44312a1abe1ee05b74ae3686b396ca43fec8c8085
	Virtual size:  3382
	SizeOfRawData:  3584
	Flags:  1107296320
	Found 3  matches: 
		Section .reloc matches in 791c0f3e7e6d9c570ad29269ec3bc3f78fadc3c1952f35eb7ac694f3e31551aa
		Section .reloc matches in 791c0f3e7e6d9c570ad29269ec3bc3f78fadc3c1952f35eb7ac694f3e31551aa
		Section .reloc matches in 258bb2b23c6ea7434eb8c965a168e7eb87257f5d3e4c4272c5ab29e873d6fbd3
-----------
Suspicious WinAPIs:

Cryptographic functions:
	 EnumSystemLocalesA
System enumeration:
	 GetSystemTimeAsFileTime
	 ReadFile
	 GetCurrentProcess
	 GetCurrentThreadId
	 GetCurrentProcessId
Process related attacks:
	 HeapReAlloc
	 HeapAlloc
	 EnumSystemLocalesA
	 HeapCreate
	 VirtualAlloc
	 GetProcAddress
Evasive behaviour:
	 EnumSystemLocalesA
	 GetProcAddress
	 Sleep
Other malware functions:
	 ShowWindow
	 GetModuleFileNameA
	 WriteFile
	 TerminateProcess
"""
