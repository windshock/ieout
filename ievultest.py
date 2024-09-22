import os
import subprocess
import time
import threading
import socket
import sys
from mitmproxy.tools.main import mitmdump
from http.server import SimpleHTTPRequestHandler, HTTPServer
import signal
import psutil
import sys

# Global variables for process and timeout control
mitmproxy_process = None
proxinjector_process = None
notepad_process = None
main_process_pid = None
timeout_occurred = False

# 프로세스 모니터링 함수
def monitor_process():
    print("[*] Monitoring processes...")
    while True:
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                # 프로세스 이름이 notepad.exe인지 확인하고, ieout 값을 명령줄에서 확인
                if proc.info['name'] == 'notepad.exe' and len(proc.info['cmdline']) > 1:
                    if proc.info['cmdline'][1] == 'ieout':  # ieout 값이 있는지 확인
                        notepad_process = proc
                        print(f"[*] Detected notepad.exe with ieout value: {proc.info['cmdline'][1]}")
                        terminate_processes(success=True)  # 프로그램 종료 호출
                        return
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        time.sleep(1)  # 1초마다 프로세스 확인

# Mitmproxy 애드온 스크립트 (Request URL을 https://windshock.github.io/invite.html로 변경)
mitmproxy_script = """
from mitmproxy import http

def request(flow: http.HTTPFlow) -> None:
    # 모든 요청을 https://windshock.github.io/invite.html로 리다이렉트
    print(f"[*] Original Request URL: {flow.request.url}")
    flow.request.url = "https://windshock.github.io/invite.html"
    print(f"[*] Redirected to: {flow.request.url}")
"""

# Mitmproxy 인증서 설치 함수
def install_mitmproxy_cert():
    home_dir = os.environ.get('USERPROFILE', '')  # %USERPROFILE% 가져오기
    mitmproxy_cert_path = os.path.join(home_dir, ".mitmproxy", "mitmproxy-ca-cert.pem")

    if os.name == 'nt':
        try:
            print(f"Installing mitmproxy certificate from {mitmproxy_cert_path} on Windows...")
            subprocess.run(f'certutil -addstore root "{mitmproxy_cert_path}"', check=True)
            print("Certificate installed successfully.")
        except subprocess.CalledProcessError as e:
            print(f"Error installing certificate: {e}")
    else:
        print("Unsupported OS for automatic certificate installation.")

# Proxinjector로 프로그램 실행
def start_proxinjector(test_file):
    global proxinjector_process
    proxinjector_cmd = [
        'proxinjector-cli.exe',
        '-e', test_file,
        '-p', '127.0.0.1:8889'
    ]
    print(f"Starting proxinjector with {test_file}...")
    proxinjector_process = subprocess.Popen(proxinjector_cmd)

# Proxinjector 백그라운드 스레드에서 실행
def start_proxinjector_thread(test_file):
    proxinjector_thread = threading.Thread(target=start_proxinjector, args=(test_file,))
    proxinjector_thread.start()

# 하위 프로세스까지 모두 강제 종료하는 함수
def kill_process_and_children(proc_pid):
    try:
        parent_proc = psutil.Process(proc_pid)
        children = parent_proc.children(recursive=True)  # 하위 프로세스 찾기
        for child in children:
            print(f"[*] Killing child process {child.pid}")
            child.kill()  # 하위 프로세스 강제 종료
        parent_proc.kill()  # 부모 프로세스 종료
        print(f"[*] Killed parent process {proc_pid}")
    except psutil.NoSuchProcess:
        print(f"[*] Process {proc_pid} does not exist.")

# 타임아웃 처리 함수
def terminate_processes(success=False):
    global mitmproxy_process, proxinjector_process, timeout_occurred
    
    if success:
        print("[*] Test successful. Terminating processes.")
    elif timeout_occurred:
        print("[*] Timeout reached. Terminating processes.")
    
    kill_process_and_children(main_process_pid)

def start_timeout_timer(timeout_seconds):
    global timeout_occurred
    timer = threading.Timer(timeout_seconds, lambda: terminate_processes())
    timer.start()

def main():
    if len(sys.argv) != 2:
        print("Usage: python ievultest.py <test_file>")
        sys.exit(1)

    test_file = sys.argv[1]
    main_process_pid = os.getpid()

    # 1. Mitmproxy 인증서 설치
    install_mitmproxy_cert()

    # 2. Proxinjector 백그라운드 실행
    start_proxinjector_thread(test_file)

    # 3. 프로세스 모니터링 시작
    monitor_thread = threading.Thread(target=monitor_process)
    monitor_thread.start()

    # 4. Mitmproxy 메인 스레드에서 SOCKS5 모드로 실행
    print("Starting mitmproxy in SOCKS5 mode...")
    with open("mitm_script.py", "w") as f:
        f.write(mitmproxy_script)

    global mitmproxy_process
    mitmproxy_process = subprocess.Popen(['mitmdump', '--mode', 'socks5', '-p', '8889', '-s', 'mitm_script.py'])

    # 5. 타임아웃 설정 (예: 10초 후 타임아웃)
    timeout_seconds = 600  # 10초 타임아웃
    start_timeout_timer(timeout_seconds)

if __name__ == "__main__":
    main()
