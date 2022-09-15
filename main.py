import pefile, ssdeep, sys, re, os, subprocess, json
from datetime import datetime
from filehash import FileHash
from pathlib import Path

if len(sys.argv) > 1:
	file = str(sys.argv[1])
else:
	print("\tUsage: " + sys.argv[0] + " sample.exe\n")
	exit()
	

class selfhash:
	def __init__(self, file):
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
		

class movefile:
	def __init__(self, file):
		if os.path.isfile(file):
			filehash = FileHash("sha256").hash_file(file)
			print("-----------\nFile moved to:")
			dirname = "files/" + filehash[0] + "/" + filehash[1]+ "/" + filehash[2]+ "/" + filehash[3]+ "/" + filehash[4]
			print(dirname + "/" + filehash)
			try:
				os.makedirs(dirname)
			except Exception:
	    			pass
			Path(file).rename(dirname + "/" + filehash)

		
class showapi:
	def __init__(self, file):
		malware = pefile.PE(file)
		apis = []
		print("-----------\nImported DLLs:")
		for entry in malware.DIRECTORY_ENTRY_IMPORT:
			print('\t' + entry.dll.decode('utf-8'))
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
				

class capait:
	def __init__(self, file):

		output = subprocess.check_output("capa -q -j " + file, shell=True).decode('ascii')
		data = json.loads(output)

		mbc = []
		
		for rulz in data['rules']:
			print("\nRule match:", rulz)
			try:
				if data['rules'][rulz]['meta']['mbc'][0]['behavior'] not in mbc:
					mbc.append(data['rules'][rulz]['meta']['mbc'][0]['behavior'])
			except Exception:
				pass
			try:
				scope = data['rules'][rulz]['meta']['scope']
			except:
				scope  = None
			try:
				offset = hex(data['rules'][rulz]['matches'][0][0]['value'])
			except:
				offset = None
			try:
				tactic = data['rules'][rulz]['meta']['attack'][0]['tactic']
			except:
				tactic = None
			try:
				tech = data['rules'][rulz]['meta']['attack'][0]['technique']
			except:
				tech = None
			try:
				subtech = data['rules'][rulz]['meta']['attack'][0]['subtechnique']
			except:
				subtech = None
			try:
				mitre = data['rules'][rulz]['meta']['attack'][0]['id']
			except:
				mitre = None
			
			if scope is not None:
				print("\tScope:", scope)
			if offset is not None:
				print("\tMatches:", offset)
			if tactic is not None:
				print("\tTactic:", tactic)
			if tech is not None:
				print("\tTechnique:", tech)
			if subtech and subtech is not None:
				print("\tSubtechnique:", subtech)
			if mitre is not None:
				print("\tMITRE:", mitre)
			
		print("-----------\ncapa Malware Behavior Catalog:")

		for behave in mbc:
			print("\t", behave)
			
			

print("""
    ____            __        ___                
   / __ \___  _____/ /_____ _/ (_)___  ___  _____
  / /_/ / _ \/ ___/ __/ __ `/ / /_  / / _ \/ ___/
 / _, _/  __/ /__/ /_/ /_/ / / / / /_/  __/ /    
/_/ |_|\___/\___/\__/\__,_/_/_/ /___/\___/_/     
""")
                                                



selfhash(file)
showapi(file)
print("""


                (`.
                 \ `.
                  )  `._..---._
\`.       __...---`         o  )
 \ `._,--'           ,    ___,'
  ) ,-._          \  )   _,-'
 /,'    ``--.._____\/--''



Capa rulz:""")
capait(file)
#movefile(file)			
