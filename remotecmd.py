import socket
import subprocess
import platform
import threading
import os
import json
import base64
import sys
from contextlib import contextmanager
import tqdm

if os.name == 'nt':  # Windows인 경우
    import ctypes
    import msvcrt
    kernel32 = ctypes.windll.kernel32
    kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
else:  # Unix 계열인 경우
    import pty
    import select
    import termios
    import struct
    import fcntl
    import tty

class RemoteCommandExecutor:
    def __init__(self, host='0.0.0.0', port=5000):
        self.host = host
        self.port = port
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.running = True  # 서버 실행 상태 플래그 추가
        
    def start_server(self):
        try:
            self.server.bind((self.host, self.port))
            self.server.listen(1)
            self.server.settimeout(1)  # 타임아웃 설정으로 주기적 체크 가능
            print(f"서버가 {self.host}:{self.port}에서 실행 중입니다.")
            print("서버 종료를 위해서는 'shutdown' 명령어를 사용하세요.")
            
            # 서버 종료 명령을 감시하는 스레드 시작
            shutdown_thread = threading.Thread(target=self.check_shutdown_command)
            shutdown_thread.daemon = True
            shutdown_thread.start()
            
            while self.running:
                try:
                    client, addr = self.server.accept()
                    print(f"클라이언트 {addr}가 연결되었습니다.")
                    client_thread = threading.Thread(target=self.handle_client, args=(client,))
                    client_thread.daemon = True
                    client_thread.start()
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:  # 정상 종료가 아닌 경우에만 에러 출력
                        print(f"연결 수락 중 오류 발생: {str(e)}")
            
            print("서버가 종료되었습니다.")
            
        except Exception as e:
            print(f"서버 시작 중 오류 발생: {str(e)}")
        finally:
            self.cleanup()
    
    def cleanup(self):
        """서버 자원 정리"""
        try:
            self.server.close()
        except:
            pass
    
    def check_shutdown_command(self):
        """서버 종료 명령을 감시하는 메서드"""
        while self.running:
            try:
                command = input().strip().lower()
                if command == 'shutdown':
                    print("서버를 종료합니다...")
                    self.shutdown()
                    break
            except:
                pass
    
    def shutdown(self):
        """서버를 안전하게 종료"""
        self.running = False
        # 서버 소켓을 닫아서 accept 블록을 해제
        try:
            # 로컬호스트로 더미 연결을 생성하여 accept 블록 해제
            dummy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            dummy_socket.connect((self.host, self.port))
            dummy_socket.close()
        except:
            pass
    
    def create_pty(self):
        if platform.system() != 'Windows':
            master_fd, slave_fd = pty.openpty()
            return master_fd, slave_fd
        return None, None
    
    def handle_client(self, client):
        try:
            master_fd, slave_fd = self.create_pty()
            shell = '/bin/bash' if platform.system() != 'Windows' else 'cmd.exe'
            
            if platform.system() != 'Windows':
                # PTY를 통한 셸 실행
                process = subprocess.Popen(
                    shell,
                    stdin=slave_fd,
                    stdout=slave_fd,
                    stderr=slave_fd,
                    preexec_fn=os.setsid,
                    shell=False
                )
                os.close(slave_fd)
            
            while self.running:  # 서버 실행 상태 확인
                try:
                    size_data = client.recv(8).decode('utf-8')
                    if not size_data:
                        break
                    
                    total_size = int(size_data)
                    received_data = ""
                    
                    while len(received_data) < total_size:
                        chunk = client.recv(4096).decode('utf-8', errors='ignore')
                        if not chunk:
                            break
                        received_data += chunk
                    
                    if not received_data:
                        break
                    
                    command_data = json.loads(received_data)
                    command_type = command_data.get('type', 'command')
                    
                    if command_type == 'terminal':
                        # 터미널 모드 처리
                        self.handle_terminal_mode(client, master_fd, command_data)
                    elif command_type == 'command':
                        if command_data.get('data', '').split()[0] in ['vi', 'vim', 'nano', 'less', 'more', 'cat']:
                            # 대화형 명령어는 터미널 모드로 처리
                            self.handle_interactive_command(client, master_fd, command_data.get('data', ''))
                        else:
                            response = self.execute_command(command_data.get('data', ''))
                            self.send_response(client, response)
                    elif command_type in ['upload', 'download', 'download_info']:
                        response = self.handle_file_transfer(command_type, command_data)
                        self.send_response(client, response)
                    
                except json.JSONDecodeError as e:
                    if self.running:  # 정상 종료가 아닌 경우에만 에러 응답
                        self.send_response(client, {
                            "status": "error",
                            "message": f"잘못된 명령어 형식입니다: {str(e)}"
                        })
                    
        except Exception as e:
            if self.running:  # 정상 종료가 아닌 경우에만 에러 출력
                print(f"클라이언트 처리 중 오류 발생: {str(e)}")
        finally:
            if master_fd is not None:
                try:
                    os.close(master_fd)
                except:
                    pass
            try:
                client.close()
            except:
                pass
    
    def handle_terminal_mode(self, client, master_fd, command_data):
        if platform.system() == 'Windows':
            return
            
        input_data = command_data.get('input', '')
        window_size = command_data.get('window_size')
        
        if window_size:
            # 터미널 윈도우 크기 설정
            winsize = struct.pack('HHHH', window_size['rows'], window_size['cols'], 0, 0)
            fcntl.ioctl(master_fd, termios.TIOCSWINSZ, winsize)
        
        if input_data:
            os.write(master_fd, input_data.encode())
        
        # 출력 읽기
        readable, _, _ = select.select([master_fd], [], [], 0.1)
        if master_fd in readable:
            try:
                output = os.read(master_fd, 1024)
                self.send_response(client, {
                    "status": "success",
                    "type": "terminal_output",
                    "data": output.decode('utf-8', errors='replace')
                })
            except OSError:
                pass

    def send_response(self, client, response):
        response_json = json.dumps(response)
        size_str = f"{len(response_json):08d}"
        client.send(size_str.encode('utf-8'))
        client.send(response_json.encode('utf-8'))

    def execute_command(self, command):
        try:
            if platform.system() == 'Windows':
                if command.lower().startswith('cd '):
                    try:
                        os.chdir(command[3:].strip())
                        output = os.getcwd()
                        error = None
                    except Exception as e:
                        output = ''
                        error = str(e)
                else:
                    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    output, error = process.communicate(timeout=30)
            else:
                process = subprocess.Popen(['/bin/bash', '-c', command], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                output, error = process.communicate(timeout=30)
            
            if error:
                return {"status": "error", "message": error}
            return {"status": "success", "message": output or os.getcwd()}
            
        except Exception as e:
            return {"status": "error", "message": str(e)}
    
    def handle_file_transfer(self, command_type, command_data):
        try:
            filename = command_data.get('filename')
            
            if command_type == 'download_info':
                return {
                    "status": "success",
                    "message": "파일 정보",
                    "file_size": os.path.getsize(filename)
                }
            
            if command_type == 'download':
                chunk_info = command_data.get('chunk_info', {})
                offset = chunk_info.get('offset', 0)
                size = chunk_info.get('size', 0)
                
                with open(filename, 'rb') as f:
                    f.seek(offset)
                    content = f.read(size)
                
                return {
                    "status": "success",
                    "message": "청크 다운로드 완료",
                    "content": base64.b64encode(content).decode('utf-8')
                }
            
            if command_type == 'upload':
                chunk_info = command_data.get('chunk_info', {})
                is_last = chunk_info.get('is_last', True)
                append_mode = chunk_info.get('append_mode', False)
                
                file_content = base64.b64decode(command_data.get('content'))
                
                mode = 'ab' if append_mode else 'wb'
                with open(filename, mode) as f:
                    f.write(file_content)
                
                if is_last:
                    return {"status": "success", "message": f"파일 '{filename}' 업로드 완료"}
                return {"status": "success", "message": "청크 업로드 완료"}
            
        except Exception as e:
            return {"status": "error", "message": f"파일 전송 실패: {str(e)}"}

    def handle_interactive_command(self, client, master_fd, command):
        if platform.system() == 'Windows':
            return self.execute_command(command)
            
        try:
            # 명령어 실행
            os.write(master_fd, f"{command}\n".encode())
            
            while True:
                readable, _, _ = select.select([master_fd], [], [], 0.1)
                if master_fd in readable:
                    try:
                        output = os.read(master_fd, 1024)
                        if output:
                            self.send_response(client, {
                                "status": "success",
                                "type": "terminal_output",
                                "data": output.decode('utf-8', errors='replace')
                            })
                    except OSError:
                        break
        except Exception as e:
            return {"status": "error", "message": str(e)}

class RemoteClient:
    def __init__(self, host='localhost', port=5000):
        self.host = host
        self.port = port
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client.settimeout(60)
        self.terminal_mode = False
        self.interactive_commands = ['vi', 'vim', 'nano', 'less', 'more', 'cat']
        
    @contextmanager
    def raw_mode(self):
        if platform.system() != 'Windows':
            fd = sys.stdin.fileno()
            old_settings = termios.tcgetattr(fd)
            try:
                tty.setraw(fd)
                yield
            finally:
                termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
        else:
            yield
    
    def get_terminal_size(self):
        try:
            if platform.system() != 'Windows':
                import fcntl
                import termios
                import struct
                h, w = struct.unpack('HHHH', 
                    fcntl.ioctl(sys.stdout.fileno(), termios.TIOCGWINSZ, struct.pack('HHHH', 0, 0, 0, 0)))[:2]
                return type('TerminalSize', (), {'columns': w, 'lines': h})()
            else:
                from shutil import get_terminal_size
                size = get_terminal_size()
                return type('TerminalSize', (), {'columns': size.columns, 'lines': size.lines})()
        except:
            return type('TerminalSize', (), {'columns': 80, 'lines': 24})()
    
    def handle_terminal_mode(self):
        with self.raw_mode():
            while self.terminal_mode:
                # 터미널 크기 전송
                size = self.get_terminal_size()
                self.send_terminal_data('', {'rows': size.lines, 'cols': size.columns})
                
                if platform.system() != 'Windows':
                    readable, _, _ = select.select([sys.stdin], [], [], 0.1)
                    if sys.stdin in readable:
                        char = sys.stdin.read(1)
                        if char == '\x1c':  # Ctrl+\
                            self.terminal_mode = False
                            break
                        self.send_terminal_data(char)
                else:
                    if msvcrt.kbhit():
                        char = msvcrt.getch().decode()
                        if char == '\x1c':  # Ctrl+\
                            self.terminal_mode = False
                            break
                        self.send_terminal_data(char)
                
                response = self.receive_response()
                if response.get('type') == 'terminal_output':
                    sys.stdout.write(response.get('data', ''))
                    sys.stdout.flush()
    
    def send_terminal_data(self, input_data, window_size=None):
        data = {
            "type": "terminal",
            "input": input_data
        }
        if window_size:
            data["window_size"] = window_size
        self.send_and_receive(data, show_response=False)
    
    def show_progress(self, total):
        return tqdm.tqdm(
            total=total,
            unit='B',
            unit_scale=True,
            unit_divisor=1024,
            leave=False,
            ncols=100,
            bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt} [{rate_fmt}]'
        )

    def connect(self):
        try:
            self.client.connect((self.host, self.port))
            print(f"서버 {self.host}:{self.port}에 연결되었습니다.")
            print("원격 명령 프롬프트에 오신 것을 환영합니다.")
            print("사용 가능한 명령어:")
            print("- 일반 명령어: 시스템 명령어 실행")
            print("- vi, nano 등: 대화형 편집기 사용 가능")
            print("- upload <로컬파일> <원격파일>: 파일 업로드")
            print("- download <원격파일> <로컬파일>: 파일 다운로드")
            print("- exit: 프로그램 종료")
            
            while True:
                try:
                    current_path = self.get_current_path()
                    command = input(f"{current_path}> ")
                    if command.lower() == 'exit':
                        break
                    
                    if command.strip() == '':
                        continue
                    
                    if command.startswith('upload '):
                        self.handle_upload_command(command)
                    elif command.startswith('download '):
                        self.handle_download_command(command)
                    else:
                        # 대화형 명령어 확인
                        cmd = command.split()[0]
                        if cmd in self.interactive_commands:
                            self.handle_interactive_mode(command)
                        else:
                            self.send_command(command)
                    
                except socket.timeout:
                    print("서버 응답 시간 초과")
                except Exception as e:
                    print(f"명령어 실행 중 오류 발생: {str(e)}")
                    break
                    
        except Exception as e:
            print(f"연결 오류: {str(e)}")
        finally:
            self.client.close()
    
    def send_command(self, command):
        command_data = {
            "type": "command",
            "data": command
        }
        self.send_and_receive(command_data)
    
    def handle_upload_command(self, command):
        try:
            parts = command.split()
            if len(parts) != 3:
                print("사용법: upload <로컬파일> <원격파일>")
                return
            
            local_file = parts[1]
            remote_file = parts[2]
            
            if not os.path.exists(local_file):
                print("로컬 파일을 찾을 수 없습니다.")
                return
            
            file_size = os.path.getsize(local_file)
            
            with open(local_file, 'rb') as f, self.show_progress(file_size) as pbar:
                chunk_size = 1024 * 1024  # 1MB
                uploaded_size = 0
                
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    
                    uploaded_size += len(chunk)
                    content = base64.b64encode(chunk).decode('utf-8')
                    
                    command_data = {
                        "type": "upload",
                        "filename": remote_file,
                        "content": content,
                        "chunk_info": {
                            "is_last": len(chunk) < chunk_size,
                            "append_mode": uploaded_size > chunk_size
                        }
                    }
                    
                    response = self.send_and_receive(command_data, show_response=False)
                    if response.get("status") == "error":
                        raise Exception(response.get("message"))
                    
                    pbar.update(len(chunk))
            
            print(f"\r파일 '{local_file}' 업로드 완료")
            
        except Exception as e:
            print(f"\r파일 업로드 실패: {str(e)}")
    
    def handle_download_command(self, command):
        try:
            parts = command.split()
            if len(parts) != 3:
                print("사용법: download <원격파일> <로컬파일>")
                return
            
            remote_file = parts[1]
            local_file = parts[2]
            
            # 파일 정보 요청
            command_data = {
                "type": "download_info",
                "filename": remote_file
            }
            
            response = self.send_and_receive(command_data)
            if response.get("status") == "error":
                print(f"파일 다운로드 실패: {response.get('message')}")
                return
                
            file_size = response.get("file_size", 0)
            print(f"\033[G\033[K파일 크기: {file_size:,} 바이트", end='')
            
            # 청크 단위로 다운로드
            chunk_size = 1024 * 1024  # 1MB
            downloaded_size = 0
            
            with open(local_file, 'wb') as f:
                while downloaded_size < file_size:
                    command_data = {
                        "type": "download",
                        "filename": remote_file,
                        "chunk_info": {
                            "offset": downloaded_size,
                            "size": chunk_size
                        }
                    }
                    
                    response = self.send_and_receive(command_data, show_response=False)
                    if response.get("status") == "error":
                        raise Exception(response.get("message"))
                    
                    chunk = base64.b64decode(response.get("content"))
                    f.write(chunk)
                    
                    downloaded_size += len(chunk)
                    self.show_progress(file_size)
            
            # 완료 메시지
            print(f"\033[G\033[K파일 '{local_file}' 다운로드 완료")
                
        except Exception as e:
            print(f"\033[G\033[K파일 다운로드 실패: {str(e)}")
            if os.path.exists(local_file):
                os.remove(local_file)  # 실패한 경우 불완전한 파일 삭제
    
    def send_and_receive(self, data, show_response=True):
        try:
            # 데이터 전송
            json_data = json.dumps(data)
            size_str = f"{len(json_data):08d}"
            self.client.send(size_str.encode('utf-8'))
            self.client.send(json_data.encode('utf-8'))
            
            # 응답 수신
            size_data = self.client.recv(8).decode('utf-8')
            if not size_data:
                raise Exception("서버로부터 응답을 받지 못했습니다.")
                
            total_size = int(size_data)
            received_data = ""
            
            while len(received_data) < total_size:
                chunk = self.client.recv(4096).decode('utf-8')
                if not chunk:
                    break
                received_data += chunk
            
            response_data = json.loads(received_data)
            
            if show_response:
                if response_data.get("status") == "error":
                    print(f"오류: {response_data.get('message')}")
                else:
                    print(response_data.get("message", ""))
            
            return response_data
            
        except Exception as e:
            print(f"통신 오류: {str(e)}")
            return {"status": "error", "message": str(e)}
    
    def get_current_path(self):
        command_data = {
            "type": "command",
            "data": "cd" if platform.system() == "Windows" else "pwd"
        }
        response = self.send_and_receive(command_data)
        return response.get("message", "").strip()

    def handle_interactive_mode(self, command):
        print("대화형 모드 시작 (종료: Ctrl+C)")
        self.terminal_mode = True
        try:
            with self.raw_mode():
                self.send_command(command)
                while self.terminal_mode:
                    if platform.system() != 'Windows':
                        if select.select([sys.stdin], [], [], 0.1)[0]:
                            char = sys.stdin.read(1)
                            if char == '\x03':  # Ctrl+C
                                self.terminal_mode = False
                                break
                            self.send_terminal_data(char)
                    else:
                        if msvcrt.kbhit():
                            char = msvcrt.getch()
                            if char == b'\x03':  # Ctrl+C
                                self.terminal_mode = False
                                break
                            self.send_terminal_data(char.decode(errors='ignore'))
                    
                    response = self.receive_response()
                    if response.get('type') == 'terminal_output':
                        sys.stdout.write(response.get('data', ''))
                        sys.stdout.flush()
        except KeyboardInterrupt:
            self.terminal_mode = False
            print("\n대화형 모드 종료")

# 서버 실행 예시
if __name__ == "__main__":
    is_server = input("서버로 실행하시겠습니까? (y/n): ").lower() == 'y'
    
    if is_server:
        server = RemoteCommandExecutor()
        try:
            server.start_server()
        except KeyboardInterrupt:
            print("\n서버를 종료합니다...")
            server.shutdown()
    else:
        server_host = input("서버 IP를 입력하세요: ")
        client = RemoteClient(host=server_host)
        client.connect()
