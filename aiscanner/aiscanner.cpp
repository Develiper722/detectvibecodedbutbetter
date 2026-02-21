// ============================================================================
// VIBECODED FREE DETECT.AC SCANNER
// Anti-Cheat Forensic Scanner
// Entropy Analysis + WinTrust Signature Verification + Prefetch + Event Log
// ============================================================================

#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif

#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0601

#include <windows.h>
#include <wintrust.h>
#include <softpub.h>
#include <wincrypt.h>
#include <commctrl.h>
#include <commdlg.h>
#include <shellapi.h>
#include <thread>
#include <vector>
#include <string>
#include <atomic>
#include <mutex>
#include <cmath>
#include <cstdio>
#include <algorithm>
#include <deque>
#include <condition_variable>
#include <map>
#include <winevt.h>

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "comdlg32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "wevtapi.lib")

#pragma comment(linker, "/subsystem:windows")

// ============================================================================
// CONSTANTS
// ============================================================================

#define IDC_PWD_EDIT       1001
#define IDC_AUTH_BTN       1002
#define IDC_SCAN_BTN       1003
#define IDC_LIST           1004
#define IDC_EXPORT_BTN     1005
#define IDC_PREFETCH_BTN   1006
#define IDC_PREFETCH_LIST  1007
#define IDC_BACK_BTN       1008
#define IDT_SCAN           2001
#define IDT_ANIM           2002
#define WM_SCAN_DONE       (WM_USER + 100)
#define WM_PREFETCH_DONE   (WM_USER + 101)
#define WM_EVENTLOG_DONE   (WM_USER + 102)
#define IDC_EVENTLOG_BTN   1009
#define IDC_EVENTLOG_LIST  1010

static const int    W_WIDTH        = 960;
static const int    W_HEIGHT       = 660;
static const int    TITLEBAR_H     = 42;
static const double ENTROPY_THRESH = 7.5;
static const DWORD64 MIN_FSIZE     = 4096;       // 4 KB
static const DWORD64 MAX_READ      = 10485760;   // 10 MB sample for entropy

// -- colour palette --
#define COL_BG          RGB(10, 10, 10)
#define COL_BG2         RGB(16, 16, 16)
#define COL_INPUT_BG    RGB(20, 20, 20)
#define COL_GREEN       RGB(0, 255, 65)
#define COL_GREEN_MID   RGB(0, 190, 48)
#define COL_GREEN_DIM   RGB(0, 130, 32)
#define COL_GREEN_DARK  RGB(0, 70, 18)
#define COL_GREEN_VDARK RGB(0, 36, 9)
#define COL_TEXT         RGB(0, 255, 65)
#define COL_TEXT_DIM     RGB(0, 140, 35)
#define COL_TEXT_XDIM    RGB(0, 80, 20)
#define COL_WHITE_DIM    RGB(170, 170, 170)
#define COL_RED          RGB(255, 55, 55)
#define COL_YELLOW       RGB(255, 200, 40)
#define COL_BORDER       RGB(0, 100, 25)

static const wchar_t* CLASS_NAME = L"DetectACScannerWnd";
static const wchar_t* PASSWORD   = L"detect.ac";

// ============================================================================
// TYPES
// ============================================================================

enum Screen { SCR_AUTH, SCR_READY, SCR_SCAN, SCR_RESULTS, SCR_PREFETCH, SCR_EVENTLOG };

struct FlaggedFile {
    std::wstring path;
    double       entropy;
    DWORD64      size;
};

struct EntropyResult {
    double value;
    bool   isPE;
};

struct PrefetchFinding {
    std::wstring path;
    std::wstring reason;
    std::wstring detail;
};

struct EventLogFinding {
    std::wstring source;    // log channel name
    std::wstring finding;   // description
    std::wstring detail;    // extra info
};

// ============================================================================
// GLOBALS
// ============================================================================

static HINSTANCE  g_inst;
static HWND       g_hwnd;
static HWND       g_editPwd;
static HWND       g_btnAuth;
static HWND       g_btnScan;
static HWND       g_listView;
static HWND       g_btnExport;
static HWND       g_btnPrefetch;
static HWND       g_listPrefetch;
static HWND       g_btnBack;
static Screen     g_screen        = SCR_AUTH;
static bool       g_badPwd        = false;
static int        g_anim          = 0;

static HFONT g_fntHuge, g_fntTitle, g_fntNorm, g_fntSub, g_fntSmall, g_fntMono;

// -- scan state (shared across threads) --
static std::vector<FlaggedFile> g_flagged;
static std::mutex               g_mtx;
static std::atomic<uint64_t>    g_scanned{0};
static std::atomic<uint64_t>    g_flaggedCount{0};
static std::atomic<bool>        g_running{false};
static std::atomic<bool>        g_done{false};

// -- thread pool --
static std::deque<std::wstring>  g_dirQueue;
static std::mutex                g_poolMtx;
static std::condition_variable   g_poolCV;
static std::condition_variable   g_doneCV;
static std::atomic<int32_t>      g_pending{0};
static bool                      g_poolStop = false;
static std::vector<std::thread>  g_workers;
static int                       g_poolSize = 0;

// -- prefetch analysis --
static std::vector<PrefetchFinding> g_pfResults;
static int g_pfMAM = 0, g_pfDup = 0, g_pfRO = 0;

// -- event log analysis --
static std::vector<EventLogFinding> g_evtResults;
static int g_evtUSN = 0, g_evtPS = 0;
static HWND g_listEventLog = nullptr;
static HWND g_btnEventLog  = nullptr;

// -- title-bar drag --
static bool  g_drag = false;
static POINT g_dragPt;

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

LRESULT CALLBACK WndProc(HWND, UINT, WPARAM, LPARAM);
static void SubmitDir(std::wstring dir);
static void ProcessDir(const std::wstring& dir);

// ============================================================================
// HELPERS
// ============================================================================

static std::wstring FmtNum(uint64_t n) {
    std::wstring s = std::to_wstring(n);
    int pos = (int)s.length() - 3;
    while (pos > 0) { s.insert(pos, L","); pos -= 3; }
    return s;
}

static std::wstring FmtSize(DWORD64 sz) {
    wchar_t b[64];
    if (sz >= 1048576ULL)       swprintf_s(b, L"%.1f MB", (double)sz / 1048576.0);
    else if (sz >= 1024ULL)     swprintf_s(b, L"%.1f KB", (double)sz / 1024.0);
    else                        swprintf_s(b, L"%llu B",  (unsigned long long)sz);
    return b;
}

// ============================================================================
// SHA-1 COMPUTATION  (WinCrypt API)
// ============================================================================

static bool ComputeSHA1(const wchar_t* path, BYTE hash[20]) {
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;

    if (!CryptAcquireContextW(&hProv, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
        return false;

    if (!CryptCreateHash(hProv, CALG_SHA1, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0);
        return false;
    }

    HANDLE hf = CreateFileW(path, GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (hf == INVALID_HANDLE_VALUE) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return false;
    }

    BYTE buf[65536];
    DWORD rd;
    while (ReadFile(hf, buf, sizeof(buf), &rd, nullptr) && rd > 0)
        CryptHashData(hHash, buf, rd, 0);
    CloseHandle(hf);

    DWORD hashLen = 20;
    BOOL ok = CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0);

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    return ok != FALSE;
}

static std::wstring SHA1Hex(const BYTE hash[20]) {
    wchar_t buf[41] = {};
    for (int i = 0; i < 20; i++)
        swprintf_s(buf + i * 2, 3, L"%02X", hash[i]);
    return buf;
}

// ============================================================================
// PREFETCH ANALYSIS
// Scans C:\Windows\Prefetch for:
//   1) Files whose first 3 bytes are 4D 41 4D  ("MAM" header)
//   2) Two or more files sharing the same SHA-1 hash
//   3) .pf files with the read-only attribute set
// ============================================================================

static void RunPrefetchAnalysis() {
    g_pfResults.clear();
    g_pfMAM = g_pfDup = g_pfRO = 0;

    const wchar_t* pfDir = L"C:\\Windows\\Prefetch\\";

    struct PFInfo {
        std::wstring path;
        std::wstring name;
        std::wstring sha1;
        bool         isMAM;
        bool         isReadOnlyPF;
    };

    std::vector<PFInfo> files;

    WIN32_FIND_DATAW fd;
    std::wstring query = std::wstring(pfDir) + L"*";
    HANDLE hFind = FindFirstFileExW(query.c_str(),
        FindExInfoBasic, &fd, FindExSearchNameMatch, nullptr, 0);
    if (hFind == INVALID_HANDLE_VALUE) {
        PostMessageW(g_hwnd, WM_PREFETCH_DONE, 0, 0);
        return;
    }

    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;

        PFInfo fi;
        fi.path = std::wstring(pfDir) + fd.cFileName;
        fi.name = fd.cFileName;
        fi.isMAM = false;
        fi.isReadOnlyPF = false;

        // 1) Check first 3 bytes for MAM header (4D 41 4D)
        HANDLE hf = CreateFileW(fi.path.c_str(), GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
        if (hf != INVALID_HANDLE_VALUE) {
            BYTE hdr[3] = {};
            DWORD rd = 0;
            if (ReadFile(hf, hdr, 3, &rd, nullptr) && rd == 3) {
                if (hdr[0] == 0x4D && hdr[1] == 0x41 && hdr[2] == 0x4D)
                    fi.isMAM = true;
            }
            CloseHandle(hf);
        }

        // 2) Compute SHA-1
        BYTE hash[20];
        if (ComputeSHA1(fi.path.c_str(), hash))
            fi.sha1 = SHA1Hex(hash);

        // 3) Check read-only on .pf files
        const wchar_t* dot = wcsrchr(fd.cFileName, L'.');
        if (dot && _wcsicmp(dot, L".pf") == 0) {
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_READONLY)
                fi.isReadOnlyPF = true;
        }

        files.push_back(std::move(fi));
    } while (FindNextFileW(hFind, &fd));
    FindClose(hFind);

    // === Build findings list ===

    // Category 1: MAM header
    for (auto& f : files) {
        if (f.isMAM) {
            g_pfResults.push_back({ f.name, L"MAM Header (4D 41 4D)", f.sha1 });
            g_pfMAM++;
        }
    }

    // Category 2: Duplicate SHA-1 hashes
    std::map<std::wstring, std::vector<std::wstring>> hashMap;
    for (auto& f : files) {
        if (!f.sha1.empty())
            hashMap[f.sha1].push_back(f.name);
    }
    for (auto& kv : hashMap) {
        if (kv.second.size() >= 2) {
            for (auto& p : kv.second) {
                g_pfResults.push_back({ p, L"Duplicate SHA-1", kv.first });
                g_pfDup++;
            }
        }
    }

    // Category 3: Read-only .pf files
    for (auto& f : files) {
        if (f.isReadOnlyPF) {
            g_pfResults.push_back({ f.name, L"Read-only .pf", f.sha1 });
            g_pfRO++;
        }
    }

    PostMessageW(g_hwnd, WM_PREFETCH_DONE, 0, 0);
}

// ============================================================================
// EVENT LOG ANALYSIS
// 1) Application log  -> Event ID 3079 = "USN Journal Deleted"
// 2) Windows PowerShell -> Event ID 403, extract HostApplication= field
// ============================================================================

static void RunEventLogAnalysis() {
    g_evtResults.clear();
    g_evtUSN = g_evtPS = 0;

    // --- 1. Application log: Event ID 3079 (USN Journal Deleted) ----------

    EVT_HANDLE hQuery = EvtQuery(NULL, L"Application",
        L"*[System[EventID=3079]]",
        EvtQueryChannelPath | EvtQueryReverseDirection);

    if (hQuery) {
        EVT_HANDLE hEvent = NULL;
        DWORD returned = 0;
        while (EvtNext(hQuery, 1, &hEvent, 2000, 0, &returned)) {
            // Render XML to get timestamp
            DWORD bufSize = 0, propCount = 0;
            EvtRender(NULL, hEvent, EvtRenderEventXml, 0, NULL, &bufSize, &propCount);
            std::wstring timeStr = L"(time unavailable)";
            if (GetLastError() == ERROR_INSUFFICIENT_BUFFER && bufSize > 0) {
                std::vector<wchar_t> buf(bufSize / sizeof(wchar_t) + 1);
                if (EvtRender(NULL, hEvent, EvtRenderEventXml, bufSize, buf.data(), &bufSize, &propCount)) {
                    std::wstring xml(buf.data());
                    // Extract SystemTime
                    size_t pos = xml.find(L"SystemTime=\"");
                    if (pos != std::wstring::npos) {
                        pos += 12; // length of SystemTime="
                        size_t end = xml.find(L"\"", pos);
                        if (end != std::wstring::npos)
                            timeStr = xml.substr(pos, end - pos);
                    }
                }
            }

            EventLogFinding f;
            f.source  = L"Application";
            f.finding = L"USN Journal Deleted";
            f.detail  = L"Event ID 3079 @ " + timeStr;
            g_evtResults.push_back(std::move(f));
            g_evtUSN++;
            EvtClose(hEvent);
            hEvent = NULL;
        }
        EvtClose(hQuery);
    }

    // --- 2. Windows PowerShell: Event ID 403 (HostApplication) -----------

    hQuery = EvtQuery(NULL, L"Windows PowerShell",
        L"*[System[EventID=403]]",
        EvtQueryChannelPath | EvtQueryReverseDirection);

    if (hQuery) {
        EVT_HANDLE hEvent = NULL;
        DWORD returned = 0;
        while (EvtNext(hQuery, 1, &hEvent, 2000, 0, &returned)) {
            DWORD bufSize = 0, propCount = 0;
            EvtRender(NULL, hEvent, EvtRenderEventXml, 0, NULL, &bufSize, &propCount);

            if (GetLastError() == ERROR_INSUFFICIENT_BUFFER && bufSize > 0) {
                std::vector<wchar_t> buf(bufSize / sizeof(wchar_t) + 1);
                if (EvtRender(NULL, hEvent, EvtRenderEventXml, bufSize, buf.data(), &bufSize, &propCount)) {
                    std::wstring xml(buf.data());

                    // Extract HostApplication= value from the EventData text
                    std::wstring hostApp;
                    size_t pos = xml.find(L"HostApplication=");
                    if (pos != std::wstring::npos) {
                        pos += 16; // length of "HostApplication="
                        // Value runs until next known key " EngineVersion="
                        size_t end = xml.find(L" EngineVersion=", pos);
                        if (end == std::wstring::npos)
                            end = xml.find(L"</Data>", pos);
                        if (end != std::wstring::npos)
                            hostApp = xml.substr(pos, end - pos);
                        else
                            hostApp = xml.substr(pos);
                    }

                    // Also extract timestamp
                    std::wstring timeStr;
                    size_t tp = xml.find(L"SystemTime=\"");
                    if (tp != std::wstring::npos) {
                        tp += 12;
                        size_t te = xml.find(L"\"", tp);
                        if (te != std::wstring::npos)
                            timeStr = xml.substr(tp, te - tp);
                    }

                    // Trim whitespace from hostApp
                    while (!hostApp.empty() && hostApp.back() == L' ')
                        hostApp.pop_back();

                    EventLogFinding f;
                    f.source  = L"Windows PowerShell";
                    f.finding = L"Powershell Script Ran: " + hostApp;
                    f.detail  = L"Event ID 403 @ " + timeStr;
                    g_evtResults.push_back(std::move(f));
                    g_evtPS++;
                }
            }
            EvtClose(hEvent);
            hEvent = NULL;
        }
        EvtClose(hQuery);
    }

    PostMessageW(g_hwnd, WM_EVENTLOG_DONE, 0, 0);
}

// ============================================================================
// DRIVE ENUMERATION
// ============================================================================

static std::vector<std::wstring> GetDrives() {
    std::vector<std::wstring> out;
    DWORD mask = GetLogicalDrives();
    for (int i = 0; i < 26; i++) {
        if (mask & (1 << i)) {
            wchar_t root[4] = { (wchar_t)(L'A' + i), L':', L'\\', 0 };
            UINT t = GetDriveTypeW(root);
            if (t == DRIVE_FIXED || t == DRIVE_REMOVABLE || t == DRIVE_REMOTE)
                out.emplace_back(root);
        }
    }
    return out;
}

// ============================================================================
// ENTROPY CALCULATION
// ============================================================================

static EntropyResult CalcEntropy(const wchar_t* path) {
    EntropyResult res = { 0.0, false };

    std::wstring lp = std::wstring(L"\\\\?\\") + path;
    HANDLE hf = CreateFileW(lp.c_str(), GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (hf == INVALID_HANDLE_VALUE) return res;

    LARGE_INTEGER li;
    if (!GetFileSizeEx(hf, &li) || li.QuadPart < (LONGLONG)MIN_FSIZE) {
        CloseHandle(hf);
        return res;
    }

    DWORD64 toRead = (DWORD64)li.QuadPart;
    if (toRead > MAX_READ) toRead = MAX_READ;

    static thread_local BYTE buf[262144];
    DWORD counts[256] = {};
    DWORD64 total = 0;
    DWORD   rd;
    bool    first = true;

    while (total < toRead &&
           ReadFile(hf, buf, (DWORD)min((DWORD64)sizeof(buf), toRead - total), &rd, nullptr) &&
           rd > 0) {
        if (first && rd >= 2) {
            res.isPE = (buf[0] == 'M' && buf[1] == 'Z');
            first = false;
        }
        for (DWORD i = 0; i < rd; i++) counts[buf[i]]++;
        total += rd;
    }
    CloseHandle(hf);
    if (total == 0) return res;

    double ent = 0.0, d = (double)total;
    for (int i = 0; i < 256; i++) {
        if (counts[i]) {
            double p = (double)counts[i] / d;
            ent -= p * log2(p);
        }
    }
    res.value = ent;
    return res;
}

// ============================================================================
// WINTRUST SIGNATURE CHECK
// ============================================================================

static bool IsSigned(const wchar_t* path) {
    std::wstring lp = std::wstring(L"\\\\?\\") + path;

    WINTRUST_FILE_INFO fi = {};
    fi.cbStruct       = sizeof(fi);
    fi.pcwszFilePath  = lp.c_str();

    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    WINTRUST_DATA wd = {};
    wd.cbStruct            = sizeof(wd);
    wd.dwUIChoice          = WTD_UI_NONE;
    wd.fdwRevocationChecks = WTD_REVOKE_NONE;
    wd.dwUnionChoice       = WTD_CHOICE_FILE;
    wd.dwStateAction       = WTD_STATEACTION_VERIFY;
    wd.dwProvFlags         = WTD_CACHE_ONLY_URL_RETRIEVAL;
    wd.pFile               = &fi;

    LONG st = WinVerifyTrust(nullptr, &action, &wd);

    wd.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(nullptr, &action, &wd);

    return (st == ERROR_SUCCESS);
}

// ============================================================================
// PARALLEL SCANNING ENGINE
// ============================================================================

static bool IsTargetExt(const wchar_t* name) {
    const wchar_t* dot = wcsrchr(name, L'.');
    if (!dot) return false;
    return (_wcsicmp(dot, L".exe") == 0 ||
            _wcsicmp(dot, L".dll") == 0 ||
            _wcsicmp(dot, L".cpl") == 0 ||
            _wcsicmp(dot, L".com") == 0 ||
            _wcsicmp(dot, L".ocx") == 0);
}

static const wchar_t* SKIP_DIRS[] = {
    L"\\Windows\\WinSxS",
    L"\\Windows\\Installer",
    L"\\Windows\\servicing",
    L"\\Windows\\assembly",
    L"\\Windows\\Logs",
    L"\\Windows\\SoftwareDistribution",
    L"\\Windows\\Fonts",
    L"\\Windows\\Microsoft.NET\\assembly",
    L"\\System Volume Information",
    L"\\Recovery",
    L"\\ProgramData\\Package Cache",
    L"\\ProgramData\\Microsoft\\Windows\\WER",
    L"\\.git\\",
    L"\\node_modules\\",
    L"\\__pycache__\\",
    L"\\.vs\\",
    L"\\windows\\assembly",
    L"\\Program Files",
    L"\\Users\\Public",
};

static bool ShouldSkipDir(const std::wstring& dir) {
    std::wstring low = dir;
    for (auto& c : low) c = towlower(c);
    for (const wchar_t* pat : SKIP_DIRS) {
        std::wstring lpat(pat);
        for (auto& c : lpat) c = towlower(c);
        if (low.find(lpat) != std::wstring::npos)
            return true;
    }
    return false;
}

static void SubmitDir(std::wstring dir) {
    g_pending.fetch_add(1, std::memory_order_acq_rel);
    {
        std::lock_guard<std::mutex> lk(g_poolMtx);
        g_dirQueue.push_back(std::move(dir));
    }
    g_poolCV.notify_one();
}

static void ProcessDir(const std::wstring& dir) {
    if (!g_running.load(std::memory_order_relaxed)) return;

    std::wstring query = L"\\\\?\\" + dir + L"*";
    WIN32_FIND_DATAW fd;
    HANDLE hf = FindFirstFileExW(query.c_str(),
        FindExInfoBasic, &fd, FindExSearchNameMatch, nullptr, FIND_FIRST_EX_LARGE_FETCH);
    if (hf == INVALID_HANDLE_VALUE) return;

    do {
        if (!g_running.load(std::memory_order_relaxed)) break;

        const wchar_t* name = fd.cFileName;

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (name[0] == L'.' && (name[1] == 0 || (name[1] == L'.' && name[2] == 0)))
                continue;
            if (_wcsicmp(name, L"$Recycle.Bin") == 0 ||
                _wcsicmp(name, L"$WinREAgent") == 0 ||
                _wcsicmp(name, L"$SysReset") == 0)
                continue;
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
                continue;

            std::wstring subdir = dir + name + L"\\";
            if (ShouldSkipDir(subdir))
                continue;

            SubmitDir(std::move(subdir));
        }
        else {
            g_scanned.fetch_add(1, std::memory_order_relaxed);

            if (!IsTargetExt(name)) continue;

            DWORD64 sz = ((DWORD64)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;
            if (sz < MIN_FSIZE) continue;

            std::wstring full = dir + name;
            EntropyResult er = CalcEntropy(full.c_str());

            if (er.value > ENTROPY_THRESH) {
                bool sig = er.isPE ? IsSigned(full.c_str()) : false;

                if (!sig) {
                    FlaggedFile ff;
                    ff.path    = std::move(full);
                    ff.entropy = er.value;
                    ff.size    = sz;
                    {
                        std::lock_guard<std::mutex> lk(g_mtx);
                        g_flagged.push_back(std::move(ff));
                    }
                    g_flaggedCount.fetch_add(1, std::memory_order_relaxed);
                }
            }
        }
    } while (FindNextFileW(hf, &fd));
    FindClose(hf);
}

static void PoolWorker() {
    while (true) {
        std::wstring dir;
        {
            std::unique_lock<std::mutex> lk(g_poolMtx);
            g_poolCV.wait(lk, [&] { return !g_dirQueue.empty() || g_poolStop; });
            if (g_poolStop && g_dirQueue.empty()) return;
            dir = std::move(g_dirQueue.front());
            g_dirQueue.pop_front();
        }
        ProcessDir(dir);
        if (g_pending.fetch_sub(1, std::memory_order_acq_rel) == 1)
            g_doneCV.notify_all();
    }
}

static void StartPool() {
    g_poolStop = false;
    g_dirQueue.clear();
    g_pending.store(0);
    int hw = (int)std::thread::hardware_concurrency();
    if (hw < 1) hw = 4;
    g_poolSize = hw * 2;
    if (g_poolSize > 64) g_poolSize = 64;
    if (g_poolSize < 4)  g_poolSize = 4;
    g_workers.reserve(g_poolSize);
    for (int i = 0; i < g_poolSize; i++)
        g_workers.emplace_back(PoolWorker);
}

static void StopPool() {
    {
        std::lock_guard<std::mutex> lk(g_poolMtx);
        g_poolStop = true;
    }
    g_poolCV.notify_all();
    for (auto& t : g_workers) { if (t.joinable()) t.join(); }
    g_workers.clear();
    g_dirQueue.clear();
}

static void BeginScan() {
    g_flagged.clear();
    g_scanned.store(0);
    g_flaggedCount.store(0);
    g_running.store(true);
    g_done.store(false);

    StartPool();

    auto drives = GetDrives();
    for (auto& d : drives)
        SubmitDir(d);

    std::thread([]() {
        {
            std::unique_lock<std::mutex> lk(g_poolMtx);
            g_doneCV.wait(lk, [] { return g_pending.load() == 0 || !g_running.load(); });
        }
        StopPool();
        g_running.store(false);
        g_done.store(true);
        PostMessageW(g_hwnd, WM_SCAN_DONE, 0, 0);
    }).detach();
}

// ============================================================================
// FONTS
// ============================================================================

static void MakeFonts() {
    auto mk = [](int sz, int weight, const wchar_t* face) {
        return CreateFontW(-sz, 0, 0, 0, weight, 0, 0, 0,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, face);
    };
    g_fntHuge  = mk(38, FW_BOLD,   L"Consolas");
    g_fntTitle = mk(26, FW_BOLD,   L"Consolas");
    g_fntNorm  = mk(15, FW_NORMAL, L"Consolas");
    g_fntSub   = mk(15, FW_NORMAL, L"Segoe UI");
    g_fntSmall = mk(12, FW_NORMAL, L"Consolas");
    g_fntMono  = mk(13, FW_NORMAL, L"Consolas");
}

static void KillFonts() {
    HFONT* ff[] = { &g_fntHuge,&g_fntTitle,&g_fntNorm,&g_fntSub,&g_fntSmall,&g_fntMono };
    for (auto* p : ff) { if (*p) { DeleteObject(*p); *p = nullptr; } }
}

// ============================================================================
// UI CONTROL LIFECYCLE
// ============================================================================

static void DestroyControls() {
    HWND* cc[] = { &g_editPwd, &g_btnAuth, &g_btnScan, &g_listView,
                   &g_btnExport, &g_btnPrefetch, &g_listPrefetch, &g_btnBack,
                   &g_listEventLog, &g_btnEventLog };
    for (auto* p : cc) {
        if (*p) { DestroyWindow(*p); *p = nullptr; }
    }
}

static void GoScreen(Screen scr) {
    DestroyControls();
    g_screen = scr;

    RECT rc; GetClientRect(g_hwnd, &rc);
    int cx = rc.right, cy = rc.bottom;

    switch (scr) {
    case SCR_AUTH: {
        int ew = 320, eh = 32;
        int ex = (cx - ew) / 2, ey = TITLEBAR_H + 300;
        g_editPwd = CreateWindowExW(0, L"EDIT", L"",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_PASSWORD | ES_CENTER | ES_AUTOHSCROLL,
            ex, ey, ew, eh, g_hwnd, (HMENU)IDC_PWD_EDIT, g_inst, nullptr);
        SendMessageW(g_editPwd, EM_SETPASSWORDCHAR, (WPARAM)L'\x2022', 0);
        SendMessageW(g_editPwd, WM_SETFONT, (WPARAM)g_fntNorm, TRUE);
        SendMessageW(g_editPwd, EM_SETLIMITTEXT, 64, 0);

        int bw = 220, bh = 42;
        g_btnAuth = CreateWindowExW(0, L"BUTTON", L"AUTHENTICATE",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW,
            (cx - bw) / 2, ey + eh + 24, bw, bh,
            g_hwnd, (HMENU)IDC_AUTH_BTN, g_inst, nullptr);
        SetFocus(g_editPwd);
        break;
    }
    case SCR_READY: {
        int bw = 300, bh = 54;
        g_btnScan = CreateWindowExW(0, L"BUTTON", L"\x25B6  START SCAN",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW,
            (cx - bw) / 2, TITLEBAR_H + 340, bw, bh,
            g_hwnd, (HMENU)IDC_SCAN_BTN, g_inst, nullptr);
        break;
    }
    case SCR_SCAN:
        SetTimer(g_hwnd, IDT_SCAN, 120, nullptr);
        SetTimer(g_hwnd, IDT_ANIM, 40, nullptr);
        break;

    case SCR_RESULTS: {
        KillTimer(g_hwnd, IDT_SCAN);
        KillTimer(g_hwnd, IDT_ANIM);

        int lx = 30, ly = TITLEBAR_H + 100;
        int lw = cx - 60, lh = cy - ly - 58;

        g_listView = CreateWindowExW(0, WC_LISTVIEW, L"",
            WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS | WS_VSCROLL,
            lx, ly, lw, lh, g_hwnd, (HMENU)IDC_LIST, g_inst, nullptr);

        ListView_SetExtendedListViewStyle(g_listView,
            LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_GRIDLINES);
        ListView_SetBkColor(g_listView, COL_BG2);
        ListView_SetTextBkColor(g_listView, COL_BG2);
        ListView_SetTextColor(g_listView, COL_GREEN);
        SendMessageW(g_listView, WM_SETFONT, (WPARAM)g_fntMono, TRUE);

        LVCOLUMNW col = {};
        col.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_FMT;

        col.pszText = (LPWSTR)L"#";
        col.cx = 50;   col.fmt = LVCFMT_RIGHT;
        ListView_InsertColumn(g_listView, 0, &col);

        col.pszText = (LPWSTR)L"File Path";
        col.cx = lw - 290; col.fmt = LVCFMT_LEFT;
        ListView_InsertColumn(g_listView, 1, &col);

        col.pszText = (LPWSTR)L"Entropy";
        col.cx = 100;  col.fmt = LVCFMT_CENTER;
        ListView_InsertColumn(g_listView, 2, &col);

        col.pszText = (LPWSTR)L"Size";
        col.cx = 120;  col.fmt = LVCFMT_RIGHT;
        ListView_InsertColumn(g_listView, 3, &col);

        {
            std::lock_guard<std::mutex> lk(g_mtx);
            std::sort(g_flagged.begin(), g_flagged.end(),
                [](const FlaggedFile& a, const FlaggedFile& b) { return a.entropy > b.entropy; });

            for (size_t i = 0; i < g_flagged.size(); i++) {
                wchar_t idx[16]; swprintf_s(idx, L"%zu", i + 1);
                LVITEMW it = {};
                it.mask = LVIF_TEXT; it.iItem = (int)i; it.pszText = idx;
                ListView_InsertItem(g_listView, &it);
                ListView_SetItemText(g_listView, (int)i, 1, (LPWSTR)g_flagged[i].path.c_str());
                wchar_t eb[32]; swprintf_s(eb, L"%.4f", g_flagged[i].entropy);
                ListView_SetItemText(g_listView, (int)i, 2, eb);
                std::wstring ss = FmtSize(g_flagged[i].size);
                ListView_SetItemText(g_listView, (int)i, 3, (LPWSTR)ss.c_str());
            }
        }

        // Bottom buttons
        int bh = 36;
        g_btnPrefetch = CreateWindowExW(0, L"BUTTON", L"PREFETCH \x25B6",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW,
            30, cy - 50, 160, bh,
            g_hwnd, (HMENU)IDC_PREFETCH_BTN, g_inst, nullptr);

        g_btnEventLog = CreateWindowExW(0, L"BUTTON", L"EVENT LOG \x25B6",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW,
            200, cy - 50, 160, bh,
            g_hwnd, (HMENU)IDC_EVENTLOG_BTN, g_inst, nullptr);

        g_btnExport = CreateWindowExW(0, L"BUTTON", L"EXPORT TO TXT",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW,
            cx - 30 - 180, cy - 50, 180, bh,
            g_hwnd, (HMENU)IDC_EXPORT_BTN, g_inst, nullptr);
        break;
    }

    case SCR_PREFETCH: {
        int lx = 30, ly = TITLEBAR_H + 110;
        int lw = cx - 60, lh = cy - ly - 58;

        g_listPrefetch = CreateWindowExW(0, WC_LISTVIEW, L"",
            WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS | WS_VSCROLL,
            lx, ly, lw, lh, g_hwnd, (HMENU)IDC_PREFETCH_LIST, g_inst, nullptr);

        ListView_SetExtendedListViewStyle(g_listPrefetch,
            LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_GRIDLINES);
        ListView_SetBkColor(g_listPrefetch, COL_BG2);
        ListView_SetTextBkColor(g_listPrefetch, COL_BG2);
        ListView_SetTextColor(g_listPrefetch, COL_GREEN);
        SendMessageW(g_listPrefetch, WM_SETFONT, (WPARAM)g_fntMono, TRUE);

        LVCOLUMNW col = {};
        col.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_FMT;

        col.pszText = (LPWSTR)L"#";
        col.cx = 40;   col.fmt = LVCFMT_RIGHT;
        ListView_InsertColumn(g_listPrefetch, 0, &col);

        col.pszText = (LPWSTR)L"File";
        col.cx = lw - 530; col.fmt = LVCFMT_LEFT;
        ListView_InsertColumn(g_listPrefetch, 1, &col);

        col.pszText = (LPWSTR)L"Finding";
        col.cx = 180;  col.fmt = LVCFMT_CENTER;
        ListView_InsertColumn(g_listPrefetch, 2, &col);

        col.pszText = (LPWSTR)L"SHA-1";
        col.cx = 290;  col.fmt = LVCFMT_LEFT;
        ListView_InsertColumn(g_listPrefetch, 3, &col);

        for (size_t i = 0; i < g_pfResults.size(); i++) {
            wchar_t idx[16]; swprintf_s(idx, L"%zu", i + 1);
            LVITEMW it = {};
            it.mask = LVIF_TEXT; it.iItem = (int)i; it.pszText = idx;
            ListView_InsertItem(g_listPrefetch, &it);
            ListView_SetItemText(g_listPrefetch, (int)i, 1, (LPWSTR)g_pfResults[i].path.c_str());
            ListView_SetItemText(g_listPrefetch, (int)i, 2, (LPWSTR)g_pfResults[i].reason.c_str());
            ListView_SetItemText(g_listPrefetch, (int)i, 3, (LPWSTR)g_pfResults[i].detail.c_str());
        }

        int bh = 36;
        g_btnBack = CreateWindowExW(0, L"BUTTON", L"\x25C0  BACK TO RESULTS",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW,
            30, cy - 50, 220, bh,
            g_hwnd, (HMENU)IDC_BACK_BTN, g_inst, nullptr);
        break;
    }

    case SCR_EVENTLOG: {
        int lx = 30, ly = TITLEBAR_H + 110;
        int lw = cx - 60, lh = cy - ly - 58;

        g_listEventLog = CreateWindowExW(0, WC_LISTVIEW, L"",
            WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS | WS_VSCROLL,
            lx, ly, lw, lh, g_hwnd, (HMENU)IDC_EVENTLOG_LIST, g_inst, nullptr);

        ListView_SetExtendedListViewStyle(g_listEventLog,
            LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_GRIDLINES);
        ListView_SetBkColor(g_listEventLog, COL_BG2);
        ListView_SetTextBkColor(g_listEventLog, COL_BG2);
        ListView_SetTextColor(g_listEventLog, COL_GREEN);
        SendMessageW(g_listEventLog, WM_SETFONT, (WPARAM)g_fntMono, TRUE);

        LVCOLUMNW col = {};
        col.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_FMT;

        col.pszText = (LPWSTR)L"#";
        col.cx = 40;   col.fmt = LVCFMT_RIGHT;
        ListView_InsertColumn(g_listEventLog, 0, &col);

        col.pszText = (LPWSTR)L"Source";
        col.cx = 160;  col.fmt = LVCFMT_LEFT;
        ListView_InsertColumn(g_listEventLog, 1, &col);

        col.pszText = (LPWSTR)L"Finding";
        col.cx = lw - 500; col.fmt = LVCFMT_LEFT;
        ListView_InsertColumn(g_listEventLog, 2, &col);

        col.pszText = (LPWSTR)L"Detail";
        col.cx = 280;  col.fmt = LVCFMT_LEFT;
        ListView_InsertColumn(g_listEventLog, 3, &col);

        for (size_t i = 0; i < g_evtResults.size(); i++) {
            wchar_t idx[16]; swprintf_s(idx, L"%zu", i + 1);
            LVITEMW it = {};
            it.mask = LVIF_TEXT; it.iItem = (int)i; it.pszText = idx;
            ListView_InsertItem(g_listEventLog, &it);
            ListView_SetItemText(g_listEventLog, (int)i, 1, (LPWSTR)g_evtResults[i].source.c_str());
            ListView_SetItemText(g_listEventLog, (int)i, 2, (LPWSTR)g_evtResults[i].finding.c_str());
            ListView_SetItemText(g_listEventLog, (int)i, 3, (LPWSTR)g_evtResults[i].detail.c_str());
        }

        int bh = 36;
        g_btnBack = CreateWindowExW(0, L"BUTTON", L"\x25C0  BACK TO RESULTS",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW,
            30, cy - 50, 220, bh,
            g_hwnd, (HMENU)IDC_BACK_BTN, g_inst, nullptr);
        break;
    }
    }
    InvalidateRect(g_hwnd, nullptr, TRUE);
}

// ============================================================================
// DRAWING - Title bar
// ============================================================================

static void PaintTitleBar(HDC dc, int w) {
    RECT rb = { 0, 0, w, TITLEBAR_H };
    HBRUSH br = CreateSolidBrush(RGB(6, 6, 6));
    FillRect(dc, &rb, br); DeleteObject(br);

    HPEN pen = CreatePen(PS_SOLID, 2, COL_GREEN_DARK);
    HPEN op  = (HPEN)SelectObject(dc, pen);
    MoveToEx(dc, 0, TITLEBAR_H - 1, nullptr);
    LineTo(dc, w, TITLEBAR_H - 1);
    SelectObject(dc, op); DeleteObject(pen);

    SetBkMode(dc, TRANSPARENT);
    SetTextColor(dc, COL_GREEN_DIM);
    HFONT of = (HFONT)SelectObject(dc, g_fntSmall);

    RECT rt = { 14, 0, w - 100, TITLEBAR_H };
    DrawTextW(dc, L"\x25C8  VIBECODED FREE DETECT.AC SCANNER", -1, &rt,
        DT_SINGLELINE | DT_VCENTER | DT_LEFT);

    SetTextColor(dc, COL_TEXT_DIM);
    SelectObject(dc, g_fntSub);

    RECT rcMin = { w - 84, 0, w - 46, TITLEBAR_H };
    DrawTextW(dc, L"\x2014", -1, &rcMin, DT_SINGLELINE | DT_VCENTER | DT_CENTER);

    RECT rcX = { w - 44, 0, w, TITLEBAR_H };
    DrawTextW(dc, L"\x2715", -1, &rcX, DT_SINGLELINE | DT_VCENTER | DT_CENTER);

    SelectObject(dc, of);
}

// ============================================================================
// DRAWING - Decorative helpers
// ============================================================================

static void DrawHLine(HDC dc, int x1, int x2, int y, COLORREF c) {
    HPEN p = CreatePen(PS_SOLID, 1, c), op = (HPEN)SelectObject(dc, p);
    MoveToEx(dc, x1, y, nullptr); LineTo(dc, x2, y);
    SelectObject(dc, op); DeleteObject(p);
}

static void DrawCornerBrackets(HDC dc, int x, int y, int w, int h, int len, COLORREF c) {
    HPEN p = CreatePen(PS_SOLID, 1, c), op = (HPEN)SelectObject(dc, p);
    MoveToEx(dc, x, y + len, nullptr); LineTo(dc, x, y); LineTo(dc, x + len, y);
    MoveToEx(dc, x + w - len, y, nullptr); LineTo(dc, x + w, y); LineTo(dc, x + w, y + len);
    MoveToEx(dc, x, y + h - len, nullptr); LineTo(dc, x, y + h); LineTo(dc, x + len, y + h);
    MoveToEx(dc, x + w - len, y + h, nullptr); LineTo(dc, x + w, y + h); LineTo(dc, x + w, y + h - len);
    SelectObject(dc, op); DeleteObject(p);
}

// ============================================================================
// DRAWING - Password screen
// ============================================================================

static void PaintAuth(HDC dc, int w, int h) {
    SetBkMode(dc, TRANSPARENT);
    HFONT of = (HFONT)SelectObject(dc, g_fntHuge);

    SetTextColor(dc, COL_GREEN);
    RECT r1 = { 0, TITLEBAR_H + 60, w, TITLEBAR_H + 110 };
    DrawTextW(dc, L"DETECT.AC", -1, &r1, DT_SINGLELINE | DT_CENTER);

    SelectObject(dc, g_fntSub);
    SetTextColor(dc, COL_TEXT_DIM);
    RECT r2 = { 0, TITLEBAR_H + 120, w, TITLEBAR_H + 145 };
    DrawTextW(dc, L"Anti-Cheat Forensic Scanner  \x2022  vibecoded edition", -1, &r2, DT_SINGLELINE | DT_CENTER);

    DrawHLine(dc, w / 2 - 160, w / 2 + 160, TITLEBAR_H + 170, COL_GREEN_DARK);
    DrawCornerBrackets(dc, w / 2 - 200, TITLEBAR_H + 190, 400, 220, 20, COL_GREEN_VDARK);

    SelectObject(dc, g_fntNorm);
    SetTextColor(dc, COL_GREEN_DIM);
    RECT r3 = { 0, TITLEBAR_H + 250, w, TITLEBAR_H + 275 };
    DrawTextW(dc, L"[ ENTER ACCESS CODE ]", -1, &r3, DT_SINGLELINE | DT_CENTER);

    if (g_editPwd) {
        RECT re; GetWindowRect(g_editPwd, &re);
        MapWindowPoints(HWND_DESKTOP, g_hwnd, (LPPOINT)&re, 2);
        InflateRect(&re, 2, 2);
        HBRUSH bb = CreateSolidBrush(g_badPwd ? COL_RED : COL_GREEN_DARK);
        FrameRect(dc, &re, bb); DeleteObject(bb);
    }

    if (g_badPwd) {
        SetTextColor(dc, COL_RED);
        RECT re = { 0, TITLEBAR_H + 420, w, TITLEBAR_H + 445 };
        DrawTextW(dc, L"\x26A0  ACCESS DENIED \x2014 INVALID CODE", -1, &re, DT_SINGLELINE | DT_CENTER);
    }

    SelectObject(dc, g_fntSmall);
    SetTextColor(dc, COL_GREEN_VDARK);
    RECT rf = { 0, h - 28, w, h };
    DrawTextW(dc, L"v1.0  //  entropy + wintrust + prefetch + eventlog", -1, &rf, DT_SINGLELINE | DT_CENTER);

    SelectObject(dc, of);
}

// ============================================================================
// DRAWING - Ready screen
// ============================================================================

static void PaintReady(HDC dc, int w, int h) {
    SetBkMode(dc, TRANSPARENT);
    HFONT of = (HFONT)SelectObject(dc, g_fntHuge);

    SetTextColor(dc, COL_GREEN);
    RECT r1 = { 0, TITLEBAR_H + 60, w, TITLEBAR_H + 110 };
    DrawTextW(dc, L"ACCESS GRANTED", -1, &r1, DT_SINGLELINE | DT_CENTER);

    SelectObject(dc, g_fntSub);
    SetTextColor(dc, COL_TEXT_DIM);
    RECT r2 = { 0, TITLEBAR_H + 120, w, TITLEBAR_H + 145 };
    DrawTextW(dc, L"System is ready for forensic analysis", -1, &r2, DT_SINGLELINE | DT_CENTER);

    DrawHLine(dc, w / 2 - 160, w / 2 + 160, TITLEBAR_H + 165, COL_GREEN_DARK);

    auto drives = GetDrives();
    int hw = (int)std::thread::hardware_concurrency();
    if (hw < 1) hw = 4;
    int threads = hw * 2;
    if (threads > 64) threads = 64;
    if (threads < 4)  threads = 4;

    int px = w / 2 - 210, py = TITLEBAR_H + 190, pw = 420, ph = 120;
    RECT rp = { px, py, px + pw, py + ph };
    HBRUSH bp = CreateSolidBrush(COL_BG2); FillRect(dc, &rp, bp); DeleteObject(bp);
    HBRUSH bb = CreateSolidBrush(COL_GREEN_DARK); FrameRect(dc, &rp, bb); DeleteObject(bb);
    DrawCornerBrackets(dc, px - 4, py - 4, pw + 8, ph + 8, 12, COL_GREEN_VDARK);

    SelectObject(dc, g_fntNorm);
    SetTextColor(dc, COL_GREEN);
    wchar_t buf[128];

    swprintf_s(buf, L"> Drives detected: %zu", drives.size());
    RECT rl1 = { px + 20, py + 15, px + pw - 20, py + 38 };
    DrawTextW(dc, buf, -1, &rl1, DT_SINGLELINE | DT_LEFT);

    SetTextColor(dc, COL_TEXT_DIM);
    swprintf_s(buf, L"> Mode: Parallel scan (%d threads)", threads);
    RECT rl2 = { px + 20, py + 42, px + pw - 20, py + 65 };
    DrawTextW(dc, buf, -1, &rl2, DT_SINGLELINE | DT_LEFT);

    RECT rl3 = { px + 20, py + 68, px + pw - 20, py + 91 };
    DrawTextW(dc, L"> Entropy threshold: 7.5 bits/byte", -1, &rl3, DT_SINGLELINE | DT_LEFT);

    RECT rl4 = { px + 20, py + 94, px + pw - 20, py + 117 };
    DrawTextW(dc, L"> Filter: .exe .dll .cpl .com .ocx", -1, &rl4, DT_SINGLELINE | DT_LEFT);

    SelectObject(dc, g_fntSmall);
    SetTextColor(dc, COL_GREEN_DARK);
    std::wstring dl = L"Targets:  ";
    for (size_t i = 0; i < drives.size(); i++) {
        if (i) dl += L"  \x2502  ";
        dl += drives[i].substr(0, 2);
    }
    RECT rd = { px, py + ph + 12, px + pw, py + ph + 30 };
    DrawTextW(dc, dl.c_str(), -1, &rd, DT_SINGLELINE | DT_CENTER);

    SelectObject(dc, of);
}

// ============================================================================
// DRAWING - Scanning screen
// ============================================================================

static void PaintScan(HDC dc, int w, int h) {
    SetBkMode(dc, TRANSPARENT);
    HFONT of = (HFONT)SelectObject(dc, g_fntHuge);

    int dots = (g_anim / 8) % 4;
    wchar_t title[32] = L"SCANNING";
    for (int i = 0; i < dots; i++) wcscat_s(title, L".");

    SetTextColor(dc, COL_GREEN);
    RECT r1 = { 0, TITLEBAR_H + 50, w, TITLEBAR_H + 100 };
    DrawTextW(dc, title, -1, &r1, DT_SINGLELINE | DT_CENTER);

    int bx = 80, by = TITLEBAR_H + 140, bw = w - 160, bh = 28;
    RECT rb = { bx, by, bx + bw, by + bh };
    HBRUSH bg = CreateSolidBrush(COL_BG2); FillRect(dc, &rb, bg); DeleteObject(bg);
    HBRUSH bdr = CreateSolidBrush(COL_GREEN_DARK); FrameRect(dc, &rb, bdr); DeleteObject(bdr);

    {
        int innerW = bw - 4;
        int glowLen = 80;
        int sweep = (g_anim * 4) % (innerW + glowLen);

        for (int i = 0; i < glowLen; i++) {
            int px = bx + 2 + sweep - glowLen + i;
            if (px < bx + 2 || px >= bx + bw - 2) continue;
            int intensity = (int)(255.0 * i / glowLen);
            RECT rs = { px, by + 3, px + 1, by + bh - 3 };
            HBRUSH bs = CreateSolidBrush(RGB(0, intensity, 0));
            FillRect(dc, &rs, bs); DeleteObject(bs);
        }
        for (int i = 0; i < 6; i++) {
            int px = bx + 2 + sweep + i;
            if (px < bx + 2 || px >= bx + bw - 2) continue;
            int intensity = 255 - (200 * i / 6);
            RECT rs = { px, by + 3, px + 1, by + bh - 3 };
            HBRUSH bs = CreateSolidBrush(RGB(0, intensity, 0));
            FillRect(dc, &rs, bs); DeleteObject(bs);
        }
    }

    SelectObject(dc, g_fntNorm);
    uint64_t scanned = g_scanned.load();
    uint64_t flagged = g_flaggedCount.load();

    int sy = by + 55;
    wchar_t buf[128];

    SetTextColor(dc, COL_GREEN);
    swprintf_s(buf, L"Files scanned:   %s", FmtNum(scanned).c_str());
    RECT rs1 = { 100, sy, w - 100, sy + 22 }; DrawTextW(dc, buf, -1, &rs1, DT_SINGLELINE | DT_LEFT);

    SetTextColor(dc, flagged > 0 ? COL_RED : COL_TEXT_DIM);
    swprintf_s(buf, L"Files flagged:   %s", FmtNum(flagged).c_str());
    RECT rs2 = { 100, sy + 28, w - 100, sy + 50 }; DrawTextW(dc, buf, -1, &rs2, DT_SINGLELINE | DT_LEFT);

    SetTextColor(dc, COL_TEXT_DIM);
    int32_t queueSize = 0;
    { std::lock_guard<std::mutex> lk(g_poolMtx); queueSize = (int32_t)g_dirQueue.size(); }
    swprintf_s(buf, L"Threads:         %d active  \x2502  %d dirs queued", g_poolSize, queueSize);
    RECT rs3 = { 100, sy + 56, w - 100, sy + 78 }; DrawTextW(dc, buf, -1, &rs3, DT_SINGLELINE | DT_LEFT);

    const wchar_t* spin[] = { L"\x2502", L"\x2571", L"\x2500", L"\x2572" };
    int si = (g_anim / 4) % 4;
    SelectObject(dc, g_fntTitle);
    SetTextColor(dc, COL_GREEN);
    RECT rsp = { w / 2 - 20, sy + 110, w / 2 + 20, sy + 150 };
    DrawTextW(dc, spin[si], -1, &rsp, DT_SINGLELINE | DT_CENTER);

    SelectObject(dc, g_fntSmall);
    SetTextColor(dc, COL_GREEN_VDARK);
    RECT ri = { 0, h - 28, w, h };
    DrawTextW(dc, L"Scanning all drives recursively  \x2022  Do not close this window", -1, &ri, DT_SINGLELINE | DT_CENTER);

    SelectObject(dc, of);
}

// ============================================================================
// DRAWING - Results screen
// ============================================================================

static void PaintResults(HDC dc, int w, int h) {
    SetBkMode(dc, TRANSPARENT);
    HFONT of = (HFONT)SelectObject(dc, g_fntTitle);

    SetTextColor(dc, COL_GREEN);
    RECT r1 = { 30, TITLEBAR_H + 12, w / 2, TITLEBAR_H + 48 };
    DrawTextW(dc, L"SCAN COMPLETE", -1, &r1, DT_SINGLELINE | DT_LEFT);

    DrawHLine(dc, 30, w - 30, TITLEBAR_H + 55, COL_GREEN_DARK);

    SelectObject(dc, g_fntNorm);
    uint64_t scanned = g_scanned.load();
    uint64_t flagged = g_flaggedCount.load();

    wchar_t buf[256];
    swprintf_s(buf, L"Scanned %s files   \x2502   %s flagged  (entropy > %.1f + unsigned)",
        FmtNum(scanned).c_str(), FmtNum(flagged).c_str(), ENTROPY_THRESH);
    SetTextColor(dc, COL_TEXT_DIM);
    RECT r2 = { 30, TITLEBAR_H + 65, w - 30, TITLEBAR_H + 88 };
    DrawTextW(dc, buf, -1, &r2, DT_SINGLELINE | DT_LEFT);

    SelectObject(dc, g_fntSmall);
    if (flagged == 0) {
        SetTextColor(dc, COL_GREEN);
        RECT rn = { 30, TITLEBAR_H + 92, w - 30, TITLEBAR_H + 110 };
        DrawTextW(dc, L"\x2714  No suspicious files detected", -1, &rn, DT_SINGLELINE | DT_LEFT);
    } else {
        SetTextColor(dc, COL_RED);
        RECT rn = { 30, TITLEBAR_H + 92, w - 30, TITLEBAR_H + 110 };
        wchar_t warn[128];
        swprintf_s(warn, L"\x26A0  %s suspicious file(s) require investigation", FmtNum(flagged).c_str());
        DrawTextW(dc, warn, -1, &rn, DT_SINGLELINE | DT_LEFT);
    }

    SelectObject(dc, of);
}

// ============================================================================
// DRAWING - Prefetch analysis screen
// ============================================================================

static void PaintPrefetch(HDC dc, int w, int h) {
    SetBkMode(dc, TRANSPARENT);
    HFONT of = (HFONT)SelectObject(dc, g_fntTitle);

    SetTextColor(dc, COL_YELLOW);
    RECT r1 = { 30, TITLEBAR_H + 12, w - 30, TITLEBAR_H + 48 };
    DrawTextW(dc, L"PREFETCH ANALYSIS", -1, &r1, DT_SINGLELINE | DT_LEFT);

    DrawHLine(dc, 30, w - 30, TITLEBAR_H + 55, COL_GREEN_DARK);

    SelectObject(dc, g_fntNorm);
    SetTextColor(dc, COL_TEXT_DIM);
    RECT r2 = { 30, TITLEBAR_H + 62, w - 30, TITLEBAR_H + 82 };
    DrawTextW(dc, L"C:\\Windows\\Prefetch", -1, &r2, DT_SINGLELINE | DT_LEFT);

    wchar_t buf[256];
    int total = (int)g_pfResults.size();

    // Category breakdown
    SelectObject(dc, g_fntSmall);
    swprintf_s(buf, L"MAM headers: %d   \x2502   Duplicate SHA-1: %d   \x2502   Read-only .pf: %d   \x2502   Total: %d",
        g_pfMAM, g_pfDup, g_pfRO, total);
    SetTextColor(dc, total > 0 ? COL_YELLOW : COL_GREEN);
    RECT r3 = { 30, TITLEBAR_H + 88, w - 30, TITLEBAR_H + 106 };
    DrawTextW(dc, buf, -1, &r3, DT_SINGLELINE | DT_LEFT);

    SelectObject(dc, of);
}

// ============================================================================
// DRAWING - Event Log analysis screen
// ============================================================================

static void PaintEventLog(HDC dc, int w, int h) {
    SetBkMode(dc, TRANSPARENT);
    HFONT of = (HFONT)SelectObject(dc, g_fntTitle);

    SetTextColor(dc, COL_YELLOW);
    RECT r1 = { 30, TITLEBAR_H + 12, w - 30, TITLEBAR_H + 48 };
    DrawTextW(dc, L"EVENT LOG ANALYSIS", -1, &r1, DT_SINGLELINE | DT_LEFT);

    DrawHLine(dc, 30, w - 30, TITLEBAR_H + 55, COL_GREEN_DARK);

    SelectObject(dc, g_fntNorm);
    SetTextColor(dc, COL_TEXT_DIM);
    RECT r2 = { 30, TITLEBAR_H + 62, w - 30, TITLEBAR_H + 82 };
    DrawTextW(dc, L"Application (ID 3079)  \x2022  Windows PowerShell (ID 403)", -1, &r2, DT_SINGLELINE | DT_LEFT);

    wchar_t buf[256];
    int total = (int)g_evtResults.size();

    SelectObject(dc, g_fntSmall);
    swprintf_s(buf, L"USN Journal Deleted: %d   \x2502   PowerShell (403): %d   \x2502   Total findings: %d",
        g_evtUSN, g_evtPS, total);
    SetTextColor(dc, total > 0 ? COL_YELLOW : COL_GREEN);
    RECT r3 = { 30, TITLEBAR_H + 88, w - 30, TITLEBAR_H + 106 };
    DrawTextW(dc, buf, -1, &r3, DT_SINGLELINE | DT_LEFT);

    SelectObject(dc, of);
}

// ============================================================================
// DRAWING - Main dispatcher (double-buffered)
// ============================================================================

static void PaintAll(HDC dc, int w, int h) {
    RECT rb = { 0, 0, w, h };
    HBRUSH bg = CreateSolidBrush(COL_BG); FillRect(dc, &rb, bg); DeleteObject(bg);

    PaintTitleBar(dc, w);

    switch (g_screen) {
    case SCR_AUTH:     PaintAuth(dc, w, h);     break;
    case SCR_READY:    PaintReady(dc, w, h);    break;
    case SCR_SCAN:     PaintScan(dc, w, h);     break;
    case SCR_RESULTS:  PaintResults(dc, w, h);  break;
    case SCR_PREFETCH: PaintPrefetch(dc, w, h); break;
    case SCR_EVENTLOG: PaintEventLog(dc, w, h); break;
    }
}

// ============================================================================
// OWNER-DRAW BUTTON
// ============================================================================

static void DrawBtn(LPDRAWITEMSTRUCT di) {
    HDC dc = di->hDC;
    RECT rc = di->rcItem;
    bool down = (di->itemState & ODS_SELECTED) != 0;
    bool focused = (di->itemState & ODS_FOCUS) != 0;

    HBRUSH bg = CreateSolidBrush(down ? COL_GREEN_DARK : COL_BG2);
    FillRect(dc, &rc, bg); DeleteObject(bg);

    HBRUSH b1 = CreateSolidBrush(focused ? COL_GREEN : COL_GREEN_DIM);
    FrameRect(dc, &rc, b1); DeleteObject(b1);
    if (focused) {
        RECT ri = rc; InflateRect(&ri, -2, -2);
        HBRUSH b2 = CreateSolidBrush(COL_GREEN_DARK);
        FrameRect(dc, &ri, b2); DeleteObject(b2);
    }

    SetBkMode(dc, TRANSPARENT);
    SetTextColor(dc, down ? COL_BG : COL_GREEN);
    HFONT of = (HFONT)SelectObject(dc, g_fntNorm);
    wchar_t txt[128]; GetWindowTextW(di->hwndItem, txt, 128);
    DrawTextW(dc, txt, -1, &rc, DT_SINGLELINE | DT_CENTER | DT_VCENTER);
    SelectObject(dc, of);
}

// ============================================================================
// EXPORT
// ============================================================================

static void ExportResults() {
    wchar_t path[MAX_PATH] = L"detect_ac_results.txt";
    OPENFILENAMEW ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner   = g_hwnd;
    ofn.lpstrFile   = path;
    ofn.nMaxFile    = MAX_PATH;
    ofn.lpstrFilter = L"Text Files\0*.txt\0All Files\0*.*\0";
    ofn.lpstrDefExt = L"txt";
    ofn.Flags       = OFN_OVERWRITEPROMPT;

    if (!GetSaveFileNameW(&ofn)) return;

    HANDLE hf = CreateFileW(path, GENERIC_WRITE, 0, nullptr,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hf == INVALID_HANDLE_VALUE) return;

    BYTE bom[] = { 0xFF, 0xFE };
    DWORD wr;
    WriteFile(hf, bom, 2, &wr, nullptr);

    auto write = [&](const std::wstring& s) {
        WriteFile(hf, s.c_str(), (DWORD)(s.size() * sizeof(wchar_t)), &wr, nullptr);
    };

    write(L"VIBECODED FREE DETECT.AC SCANNER - SCAN RESULTS\r\n");
    write(L"================================================\r\n\r\n");

    wchar_t buf[256];
    swprintf_s(buf, L"Files scanned: %s\r\n", FmtNum(g_scanned.load()).c_str());
    write(buf);

    {
        std::lock_guard<std::mutex> lk(g_mtx);
        swprintf_s(buf, L"Files flagged: %zu\r\n", g_flagged.size());
        write(buf);
        swprintf_s(buf, L"Entropy threshold: %.1f\r\n\r\n", ENTROPY_THRESH);
        write(buf);

        write(L"FILE PATH | ENTROPY | SIZE\r\n");
        write(L"------------------------------------------------------------\r\n");

        for (auto& f : g_flagged) {
            wchar_t eb[32]; swprintf_s(eb, L"%.4f", f.entropy);
            std::wstring line = f.path + L" | " + eb + L" | " + FmtSize(f.size) + L"\r\n";
            write(line);
        }
    }

    // Also include prefetch findings if available
    if (!g_pfResults.empty()) {
        write(L"\r\n\r\nPREFETCH ANALYSIS\r\n");
        write(L"=================\r\n\r\n");
        swprintf_s(buf, L"MAM headers: %d  |  Duplicate SHA-1: %d  |  Read-only .pf: %d\r\n\r\n",
            g_pfMAM, g_pfDup, g_pfRO);
        write(buf);
        write(L"FILE | FINDING | SHA-1\r\n");
        write(L"------------------------------------------------------------\r\n");
        for (auto& f : g_pfResults) {
            std::wstring line = f.path + L" | " + f.reason + L" | " + f.detail + L"\r\n";
            write(line);
        }
    }

    // Also include event log findings if available
    if (!g_evtResults.empty()) {
        write(L"\r\n\r\nEVENT LOG ANALYSIS\r\n");
        write(L"==================\r\n\r\n");
        swprintf_s(buf, L"USN Journal Deleted (3079): %d  |  PowerShell (403): %d\r\n\r\n",
            g_evtUSN, g_evtPS);
        write(buf);
        write(L"SOURCE | FINDING | DETAIL\r\n");
        write(L"------------------------------------------------------------\r\n");
        for (auto& f : g_evtResults) {
            std::wstring line = f.source + L" | " + f.finding + L" | " + f.detail + L"\r\n";
            write(line);
        }
    }

    CloseHandle(hf);
    MessageBoxW(g_hwnd, L"Results exported successfully.", L"Export", MB_OK | MB_ICONINFORMATION);
}

// ============================================================================
// WINDOW PROCEDURE
// ============================================================================

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wP, LPARAM lP) {
    switch (msg) {

    case WM_CREATE:
        g_hwnd = hwnd;
        GoScreen(SCR_AUTH);
        return 0;

    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);
        RECT rc; GetClientRect(hwnd, &rc);
        int cw = rc.right, ch = rc.bottom;

        HDC mem = CreateCompatibleDC(hdc);
        HBITMAP bmp = CreateCompatibleBitmap(hdc, cw, ch);
        HBITMAP old = (HBITMAP)SelectObject(mem, bmp);

        PaintAll(mem, cw, ch);
        BitBlt(hdc, 0, 0, cw, ch, mem, 0, 0, SRCCOPY);

        SelectObject(mem, old);
        DeleteObject(bmp);
        DeleteDC(mem);
        EndPaint(hwnd, &ps);
        return 0;
    }

    case WM_ERASEBKGND:
        return 1;

    case WM_CTLCOLOREDIT: {
        HDC hdc = (HDC)wP;
        SetTextColor(hdc, COL_GREEN);
        SetBkColor(hdc, COL_INPUT_BG);
        static HBRUSH brEdit = CreateSolidBrush(COL_INPUT_BG);
        return (LRESULT)brEdit;
    }

    case WM_DRAWITEM:
        DrawBtn((LPDRAWITEMSTRUCT)lP);
        return TRUE;

    case WM_COMMAND: {
        int id = LOWORD(wP);

        if (id == IDC_AUTH_BTN) {
            wchar_t pwd[128] = {};
            GetWindowTextW(g_editPwd, pwd, 128);
            if (wcscmp(pwd, PASSWORD) == 0) {
                g_badPwd = false;
                GoScreen(SCR_READY);
            } else {
                g_badPwd = true;
                SetWindowTextW(g_editPwd, L"");
                SetFocus(g_editPwd);
                InvalidateRect(hwnd, nullptr, FALSE);
            }
        }
        else if (id == IDC_SCAN_BTN) {
            GoScreen(SCR_SCAN);
            BeginScan();
        }
        else if (id == IDC_EXPORT_BTN) {
            ExportResults();
        }
        else if (id == IDC_PREFETCH_BTN) {
            std::thread(RunPrefetchAnalysis).detach();
        }
        else if (id == IDC_EVENTLOG_BTN) {
            std::thread(RunEventLogAnalysis).detach();
        }
        else if (id == IDC_BACK_BTN) {
            GoScreen(SCR_RESULTS);
        }
        return 0;
    }

    case WM_TIMER:
        if (wP == IDT_SCAN || wP == IDT_ANIM) {
            if (wP == IDT_ANIM) g_anim++;
            InvalidateRect(hwnd, nullptr, FALSE);
        }
        return 0;

    case WM_SCAN_DONE:
        GoScreen(SCR_RESULTS);
        return 0;

    case WM_PREFETCH_DONE:
        GoScreen(SCR_PREFETCH);
        return 0;

    case WM_EVENTLOG_DONE:
        GoScreen(SCR_EVENTLOG);
        return 0;

    case WM_LBUTTONDOWN: {
        int x = LOWORD(lP), y = HIWORD(lP);
        RECT rc; GetClientRect(hwnd, &rc);

        if (y < TITLEBAR_H) {
            if (x > rc.right - 44) {
                if (g_running.load()) {
                    if (MessageBoxW(hwnd, L"Scan in progress. Exit?",
                        L"Confirm", MB_YESNO | MB_ICONWARNING) != IDYES)
                        return 0;
                    g_running.store(false);
                }
                DestroyWindow(hwnd);
                return 0;
            }
            if (x > rc.right - 84) {
                ShowWindow(hwnd, SW_MINIMIZE);
                return 0;
            }
            g_drag = true;
            g_dragPt = { x, y };
            SetCapture(hwnd);
            return 0;
        }
        break;
    }

    case WM_MOUSEMOVE:
        if (g_drag) {
            POINT pt; GetCursorPos(&pt);
            SetWindowPos(hwnd, nullptr,
                pt.x - g_dragPt.x, pt.y - g_dragPt.y,
                0, 0, SWP_NOSIZE | SWP_NOZORDER);
        }
        return 0;

    case WM_LBUTTONUP:
        if (g_drag) { g_drag = false; ReleaseCapture(); }
        return 0;

    case WM_DESTROY:
        g_running.store(false);
        KillTimer(hwnd, IDT_SCAN);
        KillTimer(hwnd, IDT_ANIM);
        PostQuitMessage(0);
        return 0;

    default:
        break;
    }
    return DefWindowProcW(hwnd, msg, wP, lP);
}

// ============================================================================
// ENTRY POINT
// ============================================================================

int APIENTRY wWinMain(HINSTANCE hInst, HINSTANCE, LPWSTR, int nShow) {
    g_inst = hInst;

    SetProcessDPIAware();

    INITCOMMONCONTROLSEX ic = { sizeof(ic), ICC_LISTVIEW_CLASSES | ICC_PROGRESS_CLASS };
    InitCommonControlsEx(&ic);

    MakeFonts();

    WNDCLASSEXW wc = {};
    wc.cbSize        = sizeof(wc);
    wc.style         = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc   = WndProc;
    wc.hInstance      = hInst;
    wc.hCursor       = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = nullptr;
    wc.lpszClassName = CLASS_NAME;
    wc.hIcon         = LoadIcon(nullptr, IDI_SHIELD);
    wc.hIconSm       = LoadIcon(nullptr, IDI_SHIELD);
    RegisterClassExW(&wc);

    int sx = GetSystemMetrics(SM_CXSCREEN);
    int sy = GetSystemMetrics(SM_CYSCREEN);

    g_hwnd = CreateWindowExW(
        WS_EX_APPWINDOW,
        CLASS_NAME,
        L"VIBECODED FREE DETECT.AC SCANNER",
        WS_POPUP | WS_MINIMIZEBOX | WS_CLIPCHILDREN,
        (sx - W_WIDTH) / 2, (sy - W_HEIGHT) / 2,
        W_WIDTH, W_HEIGHT,
        nullptr, nullptr, hInst, nullptr);

    ShowWindow(g_hwnd, nShow);
    UpdateWindow(g_hwnd);

    if (g_editPwd) SetFocus(g_editPwd);

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        if (msg.message == WM_KEYDOWN && msg.wParam == VK_RETURN && g_screen == SCR_AUTH) {
            SendMessageW(g_hwnd, WM_COMMAND, MAKEWPARAM(IDC_AUTH_BTN, BN_CLICKED), (LPARAM)g_btnAuth);
            continue;
        }
        if (IsDialogMessageW(g_hwnd, &msg))
            continue;
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    KillFonts();
    return (int)msg.wParam;
}
