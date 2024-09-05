import wmi
import psutil
import webbrowser
import os
import time
from plyer import notification

# DLL 카테고리별로 구분
IE_DLLS_mshtml = ["mshtml.dll", "mshtmler.dll", "mshtmldac.dll", "mshtmled.dll"]
IE_DLLS_ieframe = ["ieframe.dll"]
IE_DLLS_script = ["jscript.dll", "jscript9.dll", "vbscript.dll", "ole32.dll"]
IE_DLLS_network = ["urlmon.dll"]

# 메일 전송 기록 파일 경로
SENT_EMAIL_LOG = "sent_emails.txt"

# WMI 초기화
wmi_client = wmi.WMI()


# 1. 메일 전송 기록을 확인 및 저장
def has_sent_email(program_name, pid):
    """ 이미 알림을 보낸 프로그램인지 확인 """
    if not os.path.exists(SENT_EMAIL_LOG):
        return False
    with open(SENT_EMAIL_LOG, "r") as f:
        for line in f:
            sent_name, sent_pid = line.strip().split(":")
            if sent_name == program_name and int(sent_pid) == pid:
                return True
    return False

def record_sent_email(program_name, pid):
    """ 알림을 보낸 프로그램을 기록 """
    with open(SENT_EMAIL_LOG, "a") as f:
        f.write(f"{program_name}:{pid}\n")

# 2. 프로세스에서 IE 관련 DLL 탐지
def detect_ie_usage(proc):
    try:
        found_mshtml = []
        found_ieframe = []
        found_script = []
        found_network = []

        # 프로세스가 사용하는 DLL 파일 목록 탐색
        for dll in proc.memory_maps():
            dll_path = dll.path.lower()
            if any(mshtml_dll in dll_path for mshtml_dll in IE_DLLS_mshtml):
                found_mshtml.append(dll_path)
            if any(ieframe_dll in dll_path for ieframe_dll in IE_DLLS_ieframe):
                found_ieframe.append(dll_path)
            if any(script_dll in dll_path for script_dll in IE_DLLS_script):
                found_script.append(dll_path)
            if any(network_dll in dll_path for network_dll in IE_DLLS_network):
                found_network.append(dll_path)

        # 모든 카테고리의 DLL이 포함된 경우에만 기록
        if found_mshtml and found_ieframe and found_script and found_network:
            return {
                'pid': proc.pid,
                'name': proc.name(),
                'dlls': {
                    'mshtml': found_mshtml,
                    'ieframe': found_ieframe,
                    'script': found_script,
                    'network': found_network
                }
            }
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return None

# 4. `plyer`를 사용한 지속적인 알림
def send_persistent_notification(program_name, pid):
    notification.notify(
        title="IE-related DLLs Detected",
        message=f"Program {program_name} (PID: {pid}) is using Internet Explorer-related DLLs.",
        app_name="IE Monitor",
        timeout=20  # 알림 지속 시간 (초)
    )

# 5. 기존 프로세스 검사 및 신규 프로세스 생성 이벤트 감시
def monitor_processes():
    # 1) 현재 실행 중인 프로세스 검사
    print("Checking already running processes...")
    for proc in psutil.process_iter(['pid', 'name']):
        result = detect_ie_usage(proc)
        if result and not has_sent_email(result['name'], result['pid']):
            # 검사 결과를 출력
            print(f"Program: {result['name']} (PID: {result['pid']})")
            print(f"Uses the following IE-related DLLs:")
            print(f"  - mshtml DLLs: {', '.join(result['dlls']['mshtml'])}")
            print(f"  - ieframe DLLs: {', '.join(result['dlls']['ieframe'])}")
            print(f"  - script DLLs: {', '.join(result['dlls']['script'])}")
            print(f"  - network DLLs: {', '.join(result['dlls']['network'])}")
            
            # 알림 보내기 (`win10toast` 클릭 가능 알림과 `plyer` 지속 알림)
            send_persistent_notification(result['name'], result['pid'])
            record_sent_email(result['name'], result['pid'])  # 알림 기록 저장

    # 2) WMI를 통해 신규 프로세스 감시
    print("Monitoring for new process creation events...")
    
    # WMI 쿼리를 통해 프로세스 생성 이벤트 감지
    process_watcher = wmi_client.Win32_Process.watch_for("creation")
    
    while True:
        # 새로운 프로세스가 생성될 때마다 이벤트 발생
        new_process = process_watcher()
        print(f"New process detected: {new_process.Name} (PID: {new_process.ProcessId})")

        # 5초 대기 후 DLL 검사 (DLL 로딩 시간 확보)
        time.sleep(3)
        
        try:
            proc = psutil.Process(new_process.ProcessId)
            result = detect_ie_usage(proc)
            if result and not has_sent_email(result['name'], result['pid']):
                # 검사 결과를 출력
                print(f"Program: {result['name']} (PID: {result['pid']})")
                print(f"Uses the following IE-related DLLs:")
                print(f"  - mshtml DLLs: {', '.join(result['dlls']['mshtml'])}")
                print(f"  - ieframe DLLs: {', '.join(result['dlls']['ieframe'])}")
                print(f"  - script DLLs: {', '.join(result['dlls']['script'])}")
                print(f"  - network DLLs: {', '.join(result['dlls']['network'])}")
                
                # 알림 보내기 (`win10toast` 클릭 가능 알림과 `plyer` 지속 알림)
                send_persistent_notification(result['name'], result['pid'])
                record_sent_email(result['name'], result['pid'])  # 알림 기록 저장
        except psutil.NoSuchProcess:
            print(f"Process {new_process.Name} (PID: {new_process.ProcessId}) terminated before scanning.")

# 6. 실행 로직
if __name__ == "__main__":
    print("Checking currently running processes and monitoring for new ones...")
    monitor_processes()