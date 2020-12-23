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
// �豸�����Ϣ
//
typedef struct _DevMonInfo {
  //DWORD       dev_type;
  std::string dev_name;
  bool insert;
} DevMonInfo, *PDevMonInfo;

#pragma endregion

#pragma region InnerGlobalVariables

//
// �豸���¼�����
//
static std::deque<std::shared_ptr<DevMonInfo>> g_dev_events_;

//
// �豸��ػ�����
//
static std::mutex g_dev_event_mutex;

//
// �豸��Ϣ֪ͨ
//
static std::condition_variable g_dev_event_cv_;

//
// �豸��Ϣ֪ͨ
//
static bool g_stop_flag_ = false;

#pragma endregion


// ��ʼ�豸���
bool WaitForDevEvent(std::string& dev_name, bool& insert);

// ֹͣ�豸���
bool CancelWaitForDevEvent();

} // namespace utils

#endif