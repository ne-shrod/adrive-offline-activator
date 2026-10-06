#include <windows.h>
#include <detours.h>
#include <cstring>
#include <cwchar>

#pragma comment(lib, "detours.lib")

#define MAPNAME    L"Local\\RegShimCtl.v1"
#define MAPVER     1

#define REQMAGIC   0x53484D31
#define RESPMAGIC  0x53484D32

#define FUNC_HELLO 0x0000
#define FUNC_ALLOC 0x1002

#define HINT_EMPTY 1

#define MAXSUB     512
#define MAXPIPE    128
#define MAXREPLY   8192

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

typedef wchar_t* (WINAPI* SysAllocString_t)(const wchar_t*);
typedef void      (WINAPI* SysFreeString_t)(wchar_t*);

static SysAllocString_t g_alloc = NULL;
static SysFreeString_t  g_free  = NULL;

static volatile LONG g_on = 0;
static volatile LONG g_hints = 0;

static HANDLE  g_pipe      = INVALID_HANDLE_VALUE;
static DWORD   g_lastTry   = 0;
static SRWLOCK g_pipeLock  = SRWLOCK_INIT;

static void dropPipe()
{
    if (g_pipe && g_pipe != INVALID_HANDLE_VALUE)
        CloseHandle(g_pipe);

    g_pipe = INVALID_HANDLE_VALUE;
    g_lastTry = 0;
}

static BOOL readMap(wchar_t* out, size_t cch)
{
    HANDLE section = OpenFileMappingW(FILE_MAP_READ, FALSE, MAPNAME);
    if (!section)
        return FALSE;

    const void* view = MapViewOfFile(section, FILE_MAP_READ, 0, 0, sizeof(ControlBlock));
    if (!view) {
        CloseHandle(section);
        return FALSE;
    }

    const ControlBlock* cb = (const ControlBlock*)view;

    BOOL ok = FALSE;
    if (cb->version == MAPVER && cb->pipeName[0]) {
        wcsncpy_s(out, cch, cb->pipeName, _TRUNCATE);
        ok = TRUE;
    }

    UnmapViewOfFile(const_cast<void*>(view));
    CloseHandle(section);
    return ok;
}

static BOOL connectPipeLocked()
{
    if (g_pipe && g_pipe != INVALID_HANDLE_VALUE)
        return TRUE;

    DWORD now = GetTickCount();
    if (now - g_lastTry < 250)
        return FALSE;
    g_lastTry = now;

    wchar_t name[MAXPIPE] = {0};
    if (!readMap(name, _countof(name)))
        return FALSE;

    HANDLE h = CreateFileW(name, GENERIC_READ | GENERIC_WRITE, 0, NULL,
                           OPEN_EXISTING, 0, NULL);

    if (h == INVALID_HANDLE_VALUE && GetLastError() == ERROR_PIPE_BUSY) {
        for (int i = 0; i < 20; i++) {
            if (!WaitNamedPipeW(name, 50))
                continue;

            h = CreateFileW(name, GENERIC_READ | GENERIC_WRITE, 0, NULL,
                            OPEN_EXISTING, 0, NULL);
            if (h != INVALID_HANDLE_VALUE)
                break;
        }
    }

    if (h == INVALID_HANDLE_VALUE)
        return FALSE;

    g_pipe = h;
    return TRUE;
}

static BOOL pipeCall(Request* req, ResponseHeader* rsp, BYTE* data, DWORD cap)
{
    HANDLE p = INVALID_HANDLE_VALUE;

    AcquireSRWLockExclusive(&g_pipeLock);
    if (connectPipeLocked())
        p = g_pipe;
    ReleaseSRWLockExclusive(&g_pipeLock);

    if (p == INVALID_HANDLE_VALUE)
        return FALSE;

    BOOL ok = FALSE;
    DWORD w = 0, r = 0;

    if (WriteFile(p, req, sizeof(*req), &w, NULL) && w == sizeof(*req) &&
        ReadFile(p, rsp, sizeof(*rsp), &r, NULL) && r == sizeof(*rsp) &&
        rsp->magic == RESPMAGIC)
    {
        ok = (rsp->cbData <= cap);
        if (ok && rsp->cbData) {
            DWORD got = 0;
            if (!ReadFile(p, data, rsp->cbData, &got, NULL) || got != rsp->cbData)
                ok = FALSE;
        }
    }

    if (!ok) {
        AcquireSRWLockExclusive(&g_pipeLock);
        if (g_pipe == p)
            dropPipe();
        else
            CloseHandle(p);
        ReleaseSRWLockExclusive(&g_pipeLock);
    }

    return ok;
}

static DWORD WINAPI sendHello(LPVOID)
{
    Request req;
    ResponseHeader rsp;
    memset(&req, 0, sizeof(req));
    memset(&rsp, 0, sizeof(rsp));

    req.magic    = REQMAGIC;
    req.funcId   = FUNC_HELLO;
    req.pid      = GetCurrentProcessId();
    req.threadId = GetCurrentThreadId();

    if (pipeCall(&req, &rsp, NULL, 0))
        g_hints = rsp.flags;

    return 0;
}

static wchar_t* WINAPI hookAlloc(const wchar_t* in)
{
    if (!g_alloc)
        return NULL;

    wchar_t* orig = g_alloc(in);
    if (!g_on || !in)
        return orig;

    if (in[0] == 0 && !(g_hints & HINT_EMPTY))
        return orig;

    Request req;
    memset(&req, 0, sizeof(req));
    req.magic     = REQMAGIC;
    req.funcId    = FUNC_ALLOC;
    req.status    = 0;
    req.valueType = 0;
    req.capacity  = (DWORD)(wcslen(in) * sizeof(wchar_t));
    req.pid       = GetCurrentProcessId();
    req.threadId  = GetCurrentThreadId();
    wcsncpy_s(req.subKey, MAXSUB, in, _TRUNCATE);

    ResponseHeader rsp;
    memset(&rsp, 0, sizeof(rsp));
    BYTE buf[MAXREPLY];

    if (!pipeCall(&req, &rsp, buf, sizeof(buf)) || !rsp.handled || !rsp.cbData)
        return orig;

    wchar_t text[MAXSUB];
    memset(text, 0, sizeof(text));

    DWORD chars = rsp.cbData / sizeof(wchar_t);
    if (chars > MAXSUB - 1)
        chars = MAXSUB - 1;
    memcpy(text, buf, chars * sizeof(wchar_t));

    wchar_t* repl = g_alloc(text);
    if (!repl)
        return orig;

    g_free(orig);
    return repl;
}

static BOOL resolveOleaut()
{
    HMODULE h = GetModuleHandleW(L"oleaut32.dll");
    if (!h)
        h = LoadLibraryW(L"oleaut32.dll");
    if (!h)
        return FALSE;

    g_alloc = (SysAllocString_t)GetProcAddress(h, "SysAllocString");
    g_free  = (SysFreeString_t)GetProcAddress(h, "SysFreeString");
    if (!g_alloc || !g_free)
        return FALSE;

    HMODULE owner = NULL;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                            (LPCWSTR)g_alloc, &owner) ||
        owner != h)
    {
        return FALSE;
    }

    return TRUE;
}

BOOL APIENTRY DllMain(HMODULE mod, DWORD reason, LPVOID)
{
    switch (reason) {
    case DLL_PROCESS_ATTACH: {
        DisableThreadLibraryCalls(mod);

        if (!resolveOleaut())
            return TRUE;

        if (DetourTransactionBegin() != NO_ERROR)
            return TRUE;

        DetourUpdateThread(GetCurrentThread());
        if (DetourAttach((PVOID*)&g_alloc, hookAlloc) != NO_ERROR) {
            DetourTransactionAbort();
            return TRUE;
        }

        if (DetourTransactionCommit() != NO_ERROR)
            return TRUE;

        InterlockedExchange(&g_on, 1);

        HANDLE t = CreateThread(NULL, 0, sendHello, NULL, 0, NULL);
        if (t)
            CloseHandle(t);
        break;
    }

    case DLL_PROCESS_DETACH: {
        InterlockedExchange(&g_on, 0);

        if (g_alloc) {
            if (DetourTransactionBegin() == NO_ERROR) {
                DetourUpdateThread(GetCurrentThread());
                DetourDetach((PVOID*)&g_alloc, hookAlloc);
                DetourTransactionCommit();
            }
            g_alloc = NULL;
        }

        AcquireSRWLockExclusive(&g_pipeLock);
        dropPipe();
        ReleaseSRWLockExclusive(&g_pipeLock);
        break;
    }

    default:
        break;
    }

    return TRUE;
}