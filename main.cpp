#include <windows.h>
#include <tlhelp32.h>
#include <wbemidl.h>
#include <comdef.h>
#include <oleauto.h>
#include <atomic>
#include <cstdio>
#include <cstdarg>
#include <cstring>
#include <cwchar>
#include <map>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <vector>

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "advapi32.lib")

#define MAPNAME    L"Local\\RegShimCtl.v1"
#define MAPVER     1

#define REQMAGIC   0x53484D31
#define RESPMAGIC  0x53484D32

#define FUNC_HELLO 0x0000
#define FUNC_ALLOC 0x1002

#define HINT_EMPTY 1

#define MAXSUB     512
#define MAXPIPE    128

#define HW_COUNT   3

#pragma pack(push, 1)
struct ControlBlock {
    DWORD version;
    DWORD supervisorPid;
    DWORD reserved;
    WCHAR pipeName[MAXPIPE];
    DWORD epoch;
};

struct Request {
    DWORD   magic;
    DWORD   funcId;
    DWORD   phase;
    LONG    status;
    DWORD   valueType;
    DWORD   capacity;
    DWORD   pid;
    DWORD   threadId;
    wchar_t subKey[MAXSUB];
};

struct ResponseHeader {
    DWORD magic;
    DWORD handled;
    LONG  status;
    DWORD valueType;
    DWORD cbValue;
    DWORD cbData;
    DWORD flags;
};
#pragma pack(pop)

const wchar_t kTarget[] = L"PDDTests.exe";
const wchar_t kDll[]    = L"hook.dll";

enum {
    HW_BIOS = 0,
    HW_CPU  = 1,
    HW_DISK = 2
};

const wchar_t* kTo[HW_COUNT] = {
    L"GQVOHHC5562V",
    L"PLDTQMIB9JWQ",
    L"QPC4VL2TVE6U",
};

std::map<std::wstring, std::wstring> g_map;
DWORD g_hints = 0;

wchar_t g_pipeName[MAXPIPE] = {0};
HANDLE  g_mapHandle = NULL;
std::thread g_pipeThread;
std::atomic<bool> g_pipeQuit(false);

std::mutex g_workersLock;
std::vector<std::thread> g_workers;

std::atomic<bool> g_run(true);
std::mutex g_out;

void say(const char* fmt, ...)
{
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    _vsnprintf_s(buf, sizeof(buf), _TRUNCATE, fmt, ap);
    va_end(ap);

    std::lock_guard<std::mutex> lk(g_out);
    puts(buf);
    fflush(stdout);
}

static std::wstring WA(const char* s)
{
    std::wstring w;
    if (!s)
        return w;
    for (; *s; ++s)
        w.push_back((wchar_t)(unsigned char)*s);
    return w;
}

static std::string A(const std::wstring& w)
{
    std::string s;
    s.reserve(w.size());
    for (size_t i = 0; i < w.size(); ++i) {
        wchar_t c = w[i];
        s.push_back((c >= 32 && c < 127) ? (char)c : '?');
    }
    return s;
}

static const wchar_t* diskTarget()
{
    static wchar_t buf[64];
    const DWORD n = GetEnvironmentVariableW(L"TARGET_DISK", buf, 64);
    if (n > 0 && n < 64)
        return buf;
    return L"\\\\.\\PHYSICALDRIVE0";
}

struct WmiSource {
    const char* cls;
    const char* prop;
    const char* matchProp;
    const char* matchValue;
    bool filtered;
};

static bool queryWmi(IWbemServices* svc, const WmiSource& s, std::wstring& out)
{
    const std::wstring q = L"SELECT * FROM " + WA(s.cls);

    IEnumWbemClassObject* e = NULL;
    if (FAILED(svc->ExecQuery(_bstr_t(L"WQL"), _bstr_t(q.c_str()),
                              WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                              NULL, &e)) || !e)
    {
        return false;
    }

    bool found = false;
    ULONG returned = 0;
    IWbemClassObject* obj = NULL;

    while (e->Next(WBEM_INFINITE, 1, &obj, &returned) == S_OK && returned == 1) {
        if (s.filtered) {
            VARIANT mv;
            VariantInit(&mv);

            bool ok = false;
            if (SUCCEEDED(obj->Get(_bstr_t(WA(s.matchProp).c_str()), 0, &mv, NULL, NULL))) {
                VARIANT cv;
                VariantInit(&cv);
                if (SUCCEEDED(VariantChangeType(&cv, &mv, 0, VT_BSTR))) {
                    const std::wstring got = (cv.vt == VT_BSTR && cv.bstrVal) ? cv.bstrVal : L"";
                    ok = (A(got) == s.matchValue);
                    VariantClear(&cv);
                }
                VariantClear(&mv);
            }

            if (!ok) {
                obj->Release();
                obj = NULL;
                continue;
            }
        }

        VARIANT vt;
        VariantInit(&vt);
        if (SUCCEEDED(obj->Get(_bstr_t(WA(s.prop).c_str()), 0, &vt, NULL, NULL))) {
            out = (vt.vt == VT_BSTR && vt.bstrVal) ? vt.bstrVal : L"";
            found = true;
            VariantClear(&vt);
        }

        obj->Release();
        obj = NULL;
        break;
    }

    e->Release();
    return found;
}

static IWbemServices* connectWmi()
{
    IWbemLocator* loc = NULL;

    HRESULT hr = CoCreateInstance(CLSID_WbemLocator, NULL, CLSCTX_INPROC_SERVER,
                                  IID_IWbemLocator, (void**)&loc);
    if (FAILED(hr) || !loc) {
        say("CoCreateInstance failed: 0x%08lX", (unsigned long)hr);
        return NULL;
    }

    IWbemServices* svc = NULL;
    hr = loc->ConnectServer(_bstr_t(L"root\\CIMV2"), NULL, NULL, NULL, 0, NULL, NULL, &svc);
    loc->Release();

    if (FAILED(hr) || !svc) {
        say("ConnectServer failed: 0x%08lX", (unsigned long)hr);
        return NULL;
    }

    return svc;
}

static bool diskSerialFromRegistry(std::wstring& out)
{
    struct Place { HKEY root; const wchar_t* path; const wchar_t* value; };
    static const Place kPlaces[] = {
        { HKEY_CURRENT_USER,  L"Software\\PDDTests",  L"DiskSerial" },
        { HKEY_LOCAL_MACHINE, L"SOFTWARE\\PDDTests", L"DiskSerial" },
    };

    for (const Place& p : kPlaces) {
        HKEY k = NULL;
        if (RegOpenKeyExW(p.root, p.path, 0, KEY_READ, &k) != ERROR_SUCCESS)
            continue;

        DWORD type = 0, cb = 0;
        std::wstring value;

        if (RegQueryValueExW(k, p.value, NULL, &type, NULL, &cb) == ERROR_SUCCESS &&
            cb >= sizeof(wchar_t) && cb <= MAXSUB * sizeof(wchar_t))
        {
            std::vector<wchar_t> buf(cb / sizeof(wchar_t) + 1, 0);
            if (RegQueryValueExW(k, p.value, NULL, &type,
                                 (LPBYTE)buf.data(), &cb) == ERROR_SUCCESS)
            {
                size_t chars = cb / sizeof(wchar_t);
                while (chars > 0 && buf[chars - 1] == L'\0')
                    --chars;
                value.assign(buf.data(), chars);
            }
        }

        RegCloseKey(k);

        if (!value.empty()) {
            out = value;
            return true;
        }
    }

    return false;
}

static void collectHardware(std::wstring out[HW_COUNT])
{
    char disk[64] = {0};
    const wchar_t* target = diskTarget();
    if (WideCharToMultiByte(CP_ACP, 0, target, -1, disk, sizeof(disk), NULL, NULL) <= 0)
        strcpy_s(disk, "\\\\.\\PHYSICALDRIVE0");

    const WmiSource kSources[HW_COUNT] = {
        { "Win32_BIOS",      "SerialNumber", NULL,            NULL, false },
        { "Win32_Processor", "ProcessorId",  "ProcessorType", "3",  true  },
        { "Win32_DiskDrive", "SerialNumber", "DeviceID",     disk, true  },
    };

    const bool com = SUCCEEDED(CoInitializeEx(NULL, COINIT_MULTITHREADED));

    if (com) {
        const HRESULT sec = CoInitializeSecurity(NULL, -1, NULL, NULL,
                                                RPC_C_AUTHN_LEVEL_DEFAULT,
                                                RPC_C_IMP_LEVEL_IMPERSONATE,
                                                NULL, EOAC_NONE, NULL);
        if (FAILED(sec) && sec != RPC_E_TOO_LATE)
            say("CoInitializeSecurity failed: 0x%08lX", (unsigned long)sec);

        IWbemServices* svc = connectWmi();
        if (svc) {
            for (int i = 0; i < HW_COUNT; i++)
                queryWmi(svc, kSources[i], out[i]);
            svc->Release();
        }

        CoUninitialize();
    }
    else
    {
        say("CoInitializeEx failed");
    }

    if (out[HW_DISK].empty())
        diskSerialFromRegistry(out[HW_DISK]);
}

static BOOL findRepl(const wchar_t* in, std::wstring& out)
{
    if (!in)
        return FALSE;

    std::map<std::wstring, std::wstring>::iterator it = g_map.find(in);
    if (it != g_map.end()) {
        out = it->second;
        return TRUE;
    }

    for (it = g_map.begin(); it != g_map.end(); ++it) {
        if (_wcsicmp(it->first.c_str(), in) == 0) {
            out = it->second;
            return TRUE;
        }
    }

    return FALSE;
}

static BOOL writeAll(HANDLE h, const void* p, DWORD n)
{
    const BYTE* b = (const BYTE*)p;
    while (n) {
        DWORD w = 0;
        if (!WriteFile(h, b, n, &w, NULL) || !w)
            return FALSE;

        b += w;
        n -= w;
    }

    return TRUE;
}

static BOOL readAll(HANDLE h, void* p, DWORD n)
{
    BYTE* b = (BYTE*)p;
    while (n) {
        DWORD r = 0;
        if (!ReadFile(h, b, n, &r, NULL) || !r)
            return FALSE;

        b += r;
        n -= r;
    }

    return TRUE;
}

static void answerAlloc(HANDLE p, const Request& req)
{
    ResponseHeader rsp;
    memset(&rsp, 0, sizeof(rsp));
    rsp.magic = RESPMAGIC;

    std::wstring to;
    if (!findRepl(req.subKey, to)) {
        rsp.cbValue = req.capacity;
        writeAll(p, &rsp, sizeof(rsp));
        return;
    }

    DWORD bytes = (DWORD)((to.size() + 1) * sizeof(wchar_t));
    std::vector<BYTE> data(bytes, 0);
    memcpy(data.data(), to.c_str(), to.size() * sizeof(wchar_t));

    rsp.handled   = 1;
    rsp.status    = 0;
    rsp.valueType = 0;
    rsp.cbValue   = bytes;
    rsp.cbData    = bytes;

    if (!writeAll(p, &rsp, sizeof(rsp)) || !writeAll(p, data.data(), bytes))
        return;

    char from8[512] = {0};
    char to8[512]   = {0};
    WideCharToMultiByte(CP_UTF8, 0, req.subKey, -1, from8, sizeof(from8) - 1, NULL, NULL);
    WideCharToMultiByte(CP_UTF8, 0, to.c_str(), -1, to8, sizeof(to8) - 1, NULL, NULL);
    say("pid %lu hook \"%s\" -> \"%s\"", req.pid, from8, to8);
}

static void servePipe(HANDLE p)
{
    Request req;
    while (readAll(p, &req, sizeof(req))) {
        if (req.magic != REQMAGIC)
            break;

        if (req.funcId == FUNC_HELLO) {
            ResponseHeader rsp;
            memset(&rsp, 0, sizeof(rsp));
            rsp.magic = RESPMAGIC;
            rsp.flags = g_hints;

            if (!writeAll(p, &rsp, sizeof(rsp)))
                break;
            continue;
        }

        if (req.funcId == FUNC_ALLOC) {
            answerAlloc(p, req);
            continue;
        }
    }
}

static void workerMain(HANDLE p)
{
    servePipe(p);
    DisconnectNamedPipe(p);
    CloseHandle(p);
}

static void pipeLoop()
{
    while (!g_pipeQuit) {
        HANDLE p = CreateNamedPipeW(g_pipeName,
                                    PIPE_ACCESS_DUPLEX,
                                    PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                                    PIPE_UNLIMITED_INSTANCES,
                                    4096, 4096, 5000, NULL);
        if (p == INVALID_HANDLE_VALUE)
            break;

        if (!ConnectNamedPipe(p, NULL) && GetLastError() != ERROR_PIPE_CONNECTED) {
            CloseHandle(p);
            continue;
        }

        if (g_pipeQuit) {
            CloseHandle(p);
            break;
        }

        std::lock_guard<std::mutex> lk(g_workersLock);
        g_workers.emplace_back(workerMain, p);
    }
}

static BOOL openPipe()
{
    static DWORD epoch = 0;
    epoch++;

    _snwprintf_s(g_pipeName, _countof(g_pipeName), _TRUNCATE,
                 L"\\\\.\\pipe\\regshim.%08X.%lu",
                 (unsigned)GetCurrentProcessId(), epoch);

    g_mapHandle = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE,
                                     0, (DWORD)sizeof(ControlBlock), MAPNAME);
    if (!g_mapHandle)
        return FALSE;

    void* view = MapViewOfFile(g_mapHandle, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(ControlBlock));
    if (!view)
        return FALSE;

    ControlBlock* cb = (ControlBlock*)view;
    memset(cb, 0, sizeof(*cb));
    cb->version       = MAPVER;
    cb->supervisorPid = GetCurrentProcessId();
    cb->epoch         = epoch;
    wcsncpy_s(cb->pipeName, _countof(cb->pipeName), g_pipeName, _TRUNCATE);

    UnmapViewOfFile(view);

    HANDLE probe = CreateNamedPipeW(g_pipeName,
                                    PIPE_ACCESS_DUPLEX,
                                    PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                                    PIPE_UNLIMITED_INSTANCES,
                                    4096, 4096, 5000, NULL);
    if (probe == INVALID_HANDLE_VALUE)
        return FALSE;
    CloseHandle(probe);

    g_pipeThread = std::thread(pipeLoop);
    return TRUE;
}

static void closePipe()
{
    g_pipeQuit = true;

    if (g_pipeName[0]) {
        HANDLE h = CreateFileW(g_pipeName, GENERIC_READ | GENERIC_WRITE, 0, NULL,
                               OPEN_EXISTING, 0, NULL);
        if (h != INVALID_HANDLE_VALUE)
            CloseHandle(h);
    }

    if (g_pipeThread.joinable())
        g_pipeThread.join();

    {
        std::lock_guard<std::mutex> lk(g_workersLock);
        for (size_t i = 0; i < g_workers.size(); i++) {
            if (g_workers[i].joinable())
                g_workers[i].join();
        }
        g_workers.clear();
    }

    if (g_mapHandle)
        CloseHandle(g_mapHandle);
    g_mapHandle = NULL;
}

static std::vector<DWORD> findTargets()
{
    std::vector<DWORD> out;

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return out;

    PROCESSENTRY32W e;
    memset(&e, 0, sizeof(e));
    e.dwSize = sizeof(e);

    if (Process32FirstW(snap, &e)) {
        do {
            if (_wcsicmp(e.szExeFile, kTarget) == 0)
                out.push_back(e.th32ProcessID);
        } while (Process32NextW(snap, &e));
    }

    CloseHandle(snap);
    return out;
}

static BOOL inject(DWORD pid, const wchar_t* dll)
{
    HANDLE h = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                           PROCESS_VM_OPERATION | PROCESS_VM_WRITE,
                           FALSE, pid);
    if (!h)
        return FALSE;

    BOOL ok = FALSE;
    SIZE_T bytes = (wcslen(dll) + 1) * sizeof(wchar_t);

    void* remote = VirtualAllocEx(h, NULL, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (remote) {
        SIZE_T wrote = 0;
        if (WriteProcessMemory(h, remote, dll, bytes, &wrote) && wrote == bytes) {
            HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
            FARPROC load = k32 ? GetProcAddress(k32, "LoadLibraryW") : NULL;

            if (load) {
                HANDLE t = CreateRemoteThread(h, NULL, 0,
                                              (LPTHREAD_START_ROUTINE)load,
                                              remote, 0, NULL);
                if (t) {
                    if (WaitForSingleObject(t, 5000) == WAIT_OBJECT_0) {
                        DWORD code = 0;
                        GetExitCodeThread(t, &code);
                        ok = (code != 0);
                    }
                    CloseHandle(t);
                }
            }
        }
        VirtualFreeEx(h, remote, 0, MEM_RELEASE);
    }

    CloseHandle(h);
    return ok;
}

static BOOL WINAPI onCtrl(DWORD type)
{
    if (type == CTRL_C_EVENT || type == CTRL_CLOSE_EVENT) {
        g_run = false;
        return TRUE;
    }
    return FALSE;
}

static std::wstring besideExe(const std::wstring& rel)
{
    if (rel.empty() || rel.find(L':') != std::wstring::npos)
        return rel;

    wchar_t self[MAX_PATH] = {0};
    if (!GetModuleFileNameW(NULL, self, _countof(self)))
        return rel;

    std::wstring dir(self);
    size_t slash = dir.find_last_of(L"\\/");
    if (slash == std::wstring::npos)
        return rel;

    return dir.substr(0, slash + 1) + rel;
}

int main()
{
    SetConsoleCtrlHandler(onCtrl, TRUE);

    std::wstring dll = besideExe(kDll);
    if (GetFileAttributesW(dll.c_str()) == INVALID_FILE_ATTRIBUTES) {
        say("hook.dll not found");
        return 1;
    }

    std::wstring hw[HW_COUNT];
    collectHardware(hw);

    say("disk : \"%s\"", A(hw[HW_DISK]).c_str());
    say("cpu  : \"%s\"", A(hw[HW_CPU]).c_str());
    say("bios : \"%s\"", A(hw[HW_BIOS]).c_str());

    for (int i = 0; i < HW_COUNT; i++) {
        if (!hw[i].empty())
            g_map[hw[i]] = kTo[i];
    }

    if (!openPipe()) {
        say("pipe init failed");
        return 2;
    }

    say("wait %ls", kTarget);

    std::set<DWORD> known;

    std::thread watcher([&]{
        while (g_run) {
            std::vector<DWORD> now = findTargets();
            std::set<DWORD> alive(now.begin(), now.end());

            for (std::set<DWORD>::iterator it = known.begin(); it != known.end();) {
                if (alive.count(*it))
                    ++it;
                else
                    it = known.erase(it);
            }

            for (size_t i = 0; i < now.size(); i++) {
                DWORD pid = now[i];
                if (known.count(pid))
                    continue;

                if (inject(pid, dll.c_str())) {
                    known.insert(pid);
                    say("pid %lu attached", pid);
                }
            }

            Sleep(50);
        }
    });

    while (g_run)
        Sleep(200);

    g_run = false;
    if (watcher.joinable())
        watcher.join();

    closePipe();
    return 0;
}