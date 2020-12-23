#ifndef _LS_UTILS_H_
#define _LS_UTILS_H_

#include <vector>
#include <string>
#include <locale>
#include <deque>
#include <memory>
#include <mutex>
#include <condition_variable>


namespace utils {

#pragma region InnerStructs

//
// 设备监控信息
//
typedef struct _DevMonInfo {
  //DWORD       dev_type;
  std::string dev_name;
  bool insert;
} DevMonInfo, *PDevMonInfo;

#pragma endregion

#pragma region InnerGlobalVariables

//
// 设备的事件队列
//
static std::deque<std::shared_ptr<DevMonInfo>> g_dev_events_;

//
// 设备监控互斥量
//
static std::mutex g_dev_event_mutex;

//
// 设备信息通知
//
static std::condition_variable g_dev_event_cv_;

//
// 设备信息通知
//
static bool g_stop_flag_ = false;

#pragma endregion


// 开始设备监控
bool WaitForDevEvent(std::string& dev_name, bool& insert);

// 停止设备监控
bool CancelWaitForDevEvent();

} // namespace utils

#endif