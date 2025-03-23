# APCInjector

APC注入
1.OpenProcess打开进程
2.VirtualAllocEx申请内存空间
3.WriteProcessMemory向申请的内存空间写入要注入的dll
4.GetThreadID找到线程id
5.QueueUserAPC注入对应线程的APC队列

重要代码
vector<DWORD> tids;
OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE,FALSE,pid)
QueueUserAPC
(
   GetProcAddr(GetModuleHandle(L"kernel32"),"LoadLibraryW"),
   hThread,
   (ULONG_PTR)P
);
