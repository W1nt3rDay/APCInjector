#include <Windows.h>
#include <vector>
#include <tlhelp32.h>
#include <string>
#pragma comment( linker, "/subsystem:\"windows\" /entry:\"mainCRTStartup\"" )


using namespace std;

// 通过进程名查找进程ID和所有线程ID
bool FindProcess(const wchar_t* processName, DWORD& pid, vector<DWORD>& tids) {
    pid = 0;
    tids.clear();

    // ------------------------- 查找进程PID -------------------------
    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    // 创建进程快照
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        return false;
    }

    // 遍历进程列表
    bool found = false;
    if (Process32FirstW(hProcessSnap, &pe32)) {
        do {
            // 比较进程名（不区分大小写）
            if (_wcsicmp(pe32.szExeFile, processName) == 0) {
                pid = pe32.th32ProcessID;
                found = true;
                break; // 找到第一个匹配的进程
            }
        } while (Process32NextW(hProcessSnap, &pe32));
    }
    CloseHandle(hProcessSnap);

    if (!found) return false;

    // ------------------------- 查找进程的所有线程TID -------------------------
    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);

    // 创建线程快照（遍历所有线程）
    HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hThreadSnap == INVALID_HANDLE_VALUE) {
        return false;
    }

    if (Thread32First(hThreadSnap, &te32)) {
        do {
            // 筛选属于目标进程的线程
            if (te32.th32OwnerProcessID == pid) {
                tids.push_back(te32.th32ThreadID);
            }
        } while (Thread32Next(hThreadSnap, &te32));
    }
    CloseHandle(hThreadSnap);

    return !tids.empty();
}

void APCInject(const wchar_t* processName,const wchar_t* dllPath)
{
	DWORD pid;          //进程id
	vector<DWORD> tids; //所有线程id
	if (FindProcess(processName, pid, tids))
	{
        HANDLE hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, pid);
        auto p = VirtualAllocEx(hProcess, 0, 1 << 12, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);  //申请虚拟内存
        //wchar_t buffer[] = L"D:\\Desk\\mydll.dll";
        // 2. 计算路径长度并分配内存
        size_t bufferSize = (wcslen(dllPath) + 1) * sizeof(wchar_t); // +1 为终止符
        WriteProcessMemory(hProcess, p,dllPath, bufferSize, 0);
        
        for (const auto& tid : tids)   //查找所有线程
        {
            HANDLE hThread = ::OpenThread(THREAD_SET_CONTEXT, FALSE, tid);
            if (hThread)
            {
                QueueUserAPC  //核心注入函数
                (
                    (PAPCFUNC)GetProcAddress(GetModuleHandle(L"kernel32"), "LoadLibraryW"),
                    hThread,
                    (ULONG_PTR)p
                );
            }
            CloseHandle(hThread);
        }
        VirtualFreeEx(hProcess, p, 0, MEM_RELEASE | MEM_DECOMMIT);
        CloseHandle(hProcess);
	}
}

int main()
{
    APCInject(L"ELEMENTCLIENT.EXE",L"D:\\Desk\\mydll.dll");  //传入游戏进程和要注入的DLL文件路径
    return 0;
}