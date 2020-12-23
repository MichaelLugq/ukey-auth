#include "device_monitor.h"

#include <windows.h>
#include <setupapi.h>
#include <initguid.h>
#include <devguid.h>    // for GUID_DEVCLASS_CDROM etc
#include <setupapi.h>
#include <cfgmgr32.h>   // for MAX_DEVICE_ID_LEN, CM_Get_Parent and CM_Get_Device_ID
#include <Winioctl.h>
#include <setupapi.h>
#include <ntddscsi.h>
#include <iomanip>
#include <stdio.h>
#include <tchar.h>
#include <strsafe.h>
#include <dbt.h>

#include <memory>
#include <thread>
#include <deque>
#include <mutex>
#include <algorithm>
#include <codecvt>

#pragma comment(lib, "setupapi.lib")

static const std::string& kLSSDFlag = "lssd";

namespace utils {

#pragma region StrConvt

inline std::string w2mb(const wchar_t* wstr) {
  std::mbstate_t state = std::mbstate_t();
  std::size_t len = std::wcsrtombs(nullptr, &wstr, 0, &state);
  if (len == static_cast<size_t>(-1)) {
    return std::string();
  }
  std::string mbstr(len, '\0');
  std::wcsrtombs(&mbstr[0], &wstr, mbstr.size(), &state);
  return mbstr;
}

inline std::string w2mb(const std::wstring& wstr) {
  return w2mb(wstr.c_str());
}

inline std::wstring mb2w(const char* mbstr) {
  std::mbstate_t state = std::mbstate_t();
  std::size_t len = std::mbsrtowcs(nullptr, &mbstr, 0, &state);
  if (len == static_cast<size_t>(-1)) {
    return std::wstring();
  }
  std::wstring wstr(len, L'\0');
  std::mbsrtowcs(&wstr[0], &mbstr, wstr.size(), &state);
  return wstr;
}

inline std::wstring mb2w(const std::string& mbstr) {
  return mb2w(mbstr.c_str());
}

#pragma endregion

#pragma region DeviceMonitor

//
// 用于设备监控的窗口类的名称
//
#define WND_CLASS_NAME TEXT("LSDeviceMonitorWindowClass")

//
// 设备通知事件句柄
//
static std::thread g_thread;

//
// 关闭消息（防止被其他关闭消息关闭）
//
#define WM_LS_CLOSE (WM_USER + 0x12)

//
// 设备事件监控窗口句柄
//
static HWND g_dev_mon_hwnd;

//
// 注册设备插拔通知
//
bool RegisterDeviceNotificationToHwnd(
  IN GUID InterfaceClassGuid, IN HWND hWnd, OUT HDEVNOTIFY *hDeviceNotify
) {
  DEV_BROADCAST_DEVICEINTERFACE NotificationFilter;

  ZeroMemory(&NotificationFilter, sizeof(NotificationFilter));
  NotificationFilter.dbcc_size = sizeof(DEV_BROADCAST_DEVICEINTERFACE);
  NotificationFilter.dbcc_devicetype = DBT_DEVTYP_DEVICEINTERFACE;
  NotificationFilter.dbcc_classguid = CdRomClassGuid;// InterfaceClassGuid;

  *hDeviceNotify = ::RegisterDeviceNotification(
                     hWnd,                       // events recipient
                     &NotificationFilter,        // type of device
                     DEVICE_NOTIFY_WINDOW_HANDLE // type of recipient handle
                   );

  if (NULL == *hDeviceNotify) {
    return false;
  }

  return true;
}

//
// 掩码转盘符，用于监控盘符变更（增、删）
//
char GetVolumeFromMask(DWORD mask) {
  char volume = 0;
  for (int i = 0; i < 26; ++i) {
    if (BitTest((long const *)&mask, i)) {
      volume = 'A' + i;
    }
  }
  return volume;
}

//
// 处理设备事件
//
int HandleChanges(UINT message, WPARAM wParam, LPARAM lParam) {
  if (wParam != DBT_DEVICEARRIVAL && wParam != DBT_DEVICEREMOVECOMPLETE) {
    return 1;
  }

  if (!lParam) {
    return 1;
  }

  PDEV_BROADCAST_HDR pdev_hdr = (PDEV_BROADCAST_HDR)lParam;
  if (pdev_hdr->dbch_devicetype != DBT_DEVTYP_DEVICEINTERFACE) {
    return 1;
  }

  PDEV_BROADCAST_DEVICEINTERFACE pdev_inf;
  pdev_inf = (PDEV_BROADCAST_DEVICEINTERFACE)pdev_hdr;

  auto info = std::make_shared<DevMonInfo>();
  info->dev_name = (pdev_inf->dbcc_name);
  std::transform(info->dev_name.begin(), info->dev_name.end(), info->dev_name.begin(), ::tolower);
  //info->dev_type = pdev_inf->dbcc_devicetype;
  info->insert = (wParam == DBT_DEVICEARRIVAL);

  auto dev_path = info->dev_name;
  std::transform(dev_path.begin(), dev_path.end(), dev_path.begin(), ::tolower);

  if (dev_path.find("lssd") != std::string::npos) {
    std::unique_lock<std::mutex> lock(g_dev_event_mutex);
    g_dev_events_.emplace_back(std::move(info));
    lock.unlock();
    g_dev_event_cv_.notify_one();
  }

  return 1;
}

//
// 消息处理
//
INT_PTR WINAPI WinProcCallback(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam) {
  switch (message) {
  case WM_DEVICECHANGE:
    return HandleChanges(message, wParam, lParam);
  }
  return DefWindowProc(hWnd, message, wParam, lParam);
}

//
// 初始化窗口类
//
bool InitWindowClass() {
  WNDCLASSEX wnd_cls;
  ZeroMemory(&wnd_cls, sizeof(wnd_cls));

  wnd_cls.cbSize = sizeof(WNDCLASSEX);
  wnd_cls.hInstance = reinterpret_cast<HINSTANCE>(GetModuleHandle(0));
  wnd_cls.lpfnWndProc = reinterpret_cast<WNDPROC>(WinProcCallback);
  wnd_cls.lpszClassName = WND_CLASS_NAME;

  if (!RegisterClassEx(&wnd_cls)) {
    return false;
  }
  return true;
}

//
// 创建窗口
//
bool CreateTheWindow(HWND& hWnd) {
  hWnd = CreateWindowEx(
           WS_EX_CLIENTEDGE | WS_EX_APPWINDOW,
           WND_CLASS_NAME,
           nullptr,
           WS_OVERLAPPEDWINDOW, // style
           CW_USEDEFAULT, 0,
           640, 480,
           NULL, NULL,
           reinterpret_cast<HINSTANCE>(GetModuleHandle(0)),
           NULL);
  if (hWnd == NULL) {
    return false;
  }
  return true;
}

//
// 消息转发
//
void MessageLoop(HWND hWnd) {
  MSG msg;

  // Get all messages for any window that belongs to this thread,
  // without any filtering. Potential optimization could be
  // obtained via use of filter values if desired.

  while (GetMessageW(&msg, hWnd, 0, 0)) {
    if (msg.message == WM_LS_CLOSE) {
      break;
    }
    TranslateMessage(&msg);
    if (msg.message == WM_LS_CLOSE) {
      break;
    }
    DispatchMessage(&msg);
    if (msg.message == WM_LS_CLOSE) {
      break;
    }
  }
}

//
// 初始化监控
//
bool InitDevMon() {
  if (g_thread.joinable()) {
    return true;
  }

  static bool running = false;

  if (running) {
    return true;
  }

  HANDLE hwait = ::CreateEventW(NULL, FALSE, FALSE, NULL);

  g_thread = std::thread([=]() {

    if (!InitWindowClass()) {
      return false;
    }

    if (!CreateTheWindow(g_dev_mon_hwnd)) {
      return false;
    }

    static HDEVNOTIFY hDeviceNotify;
    if (!RegisterDeviceNotificationToHwnd(CdRomClassGuid, g_dev_mon_hwnd, &hDeviceNotify)) {
      return false;
    }

    running = true;

    if (!::SetEvent(hwait)) {
      // How to do??
    }

    MessageLoop(g_dev_mon_hwnd);

    running = false;

    if (!UnregisterDeviceNotification(hDeviceNotify)) {
      //return /*false*/;
    }

    return true;
  });

  // Wait for "running"
  DWORD rv = ::WaitForSingleObject(hwait, INFINITE);
  if (rv != WAIT_OBJECT_0) {
    return false;
  }

  return true;
}

//
// 取消设备监控
//
bool CancelDevMon() {
  if (!g_thread.joinable()) {
    return true;
  }
  g_stop_flag_ = true;
  g_dev_event_cv_.notify_all();

  ::PostMessage(g_dev_mon_hwnd, WM_LS_CLOSE, NULL, NULL);

  g_thread.join();

  return true;
}

// 开始设备监控
bool WaitForDevEvent(std::string& dev_name, bool& insert) {
  if (!InitDevMon()) {
    return false;
  }

  {
    std::unique_lock<std::mutex> lock(g_dev_event_mutex);
    g_dev_event_cv_.wait(lock, [&]() { return g_stop_flag_ || !g_dev_events_.empty(); });

    if (g_stop_flag_) {
      return false;
    }

    dev_name = g_dev_events_.front()->dev_name;
    insert = g_dev_events_.front()->insert;
    g_dev_events_.pop_front();
  }

  return true;
}

// 停止设备监控
bool CancelWaitForDevEvent() {
  return CancelDevMon();
}


#pragma endregion

} // namespace utils