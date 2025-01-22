import socket
import subprocess
import platform
import threading
import os
import json
import base64
import sys
import signal
import struct
import select
import time
from contextlib import contextmanager

# 운영체제별 모듈 임포트
if os.name == 'nt':  # Windows
    import msvcrt
    import ctypes
    kernel32 = ctypes.windll.kernel32
    kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
else:  # Unix/Linux
    import fcntl
    import termios
    import pty
    import tty

class TerminalSize:
    """터미널 크기 관리 클래스"""
    @staticmethod
    def get_terminal_size():
        if os.name == 'nt':
            try:
                from shutil import get_terminal_size
                size = get_terminal_size()
                return size.lines, size.columns
            except:
                return 24, 80
        else:
            try:
                import fcntl
                import termios
                import struct
                size = struct.unpack('hh', fcntl.ioctl(sys.stdout.fileno(), termios.TIOCGWINSZ, '1234'))
                return size[0], size[1]
            except:
                return 24, 80

class PtyHandler:
    """PTY 세션 관리 클래스"""
    def __init__(self):
        self.master_fd = None
        self.slave_fd = None
        self.process = None
        self.is_windows = os.name == 'nt'
        
    def create(self):
        """PTY 생성"""
        if not self.is_windows:
            self.master_fd, self.slave_fd = pty.openpty()
            # PTY 설정
            attr = termios.tcgetattr(self.slave_fd)
            attr[3] = attr[3] & ~termios.ECHO
            termios.tcsetattr(self.slave_fd, termios.TCSANOW, attr)
            return True
        return False
        
    def spawn(self, shell=None):
        """셸 프로세스 생성"""
        if not shell:
            shell = 'cmd.exe' if self.is_windows else '/bin/bash'
            
        if self.is_windows:
            self.process = subprocess.Popen(
                shell,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=True
            )
            return True
        else:
            env = {
                'TERM': 'xterm-256color',
                'PATH': os.environ.get('PATH', ''),
                'HOME': os.environ.get('HOME', ''),
                'SHELL': shell
            }
            
            self.process = subprocess.Popen(
                shell,
                stdin=self.slave_fd,
                stdout=self.slave_fd,
                stderr=self.slave_fd,
                preexec_fn=os.setsid,
                env=env,
                shell=False
            )
            os.close(self.slave_fd)
            return True
        
    def resize(self, rows, cols):
        """터미널 크기 조정"""
        if not self.is_windows and self.master_fd:
            winsize = struct.pack('HHHH', rows, cols, 0, 0)
            fcntl.ioctl(self.master_fd, termios.TIOCSWINSZ, winsize)
            
    def read(self, size=1024):
        """데이터 읽기"""
        if self.is_windows:
            if self.process:
                try:
                    return self.process.stdout.read1(size)
                except:
                    return None
        else:
            if self.master_fd:
                try:
                    return os.read(self.master_fd, size)
                except:
                    return None
        return None
        
    def write(self, data):
        """데이터 쓰기"""
        if self.is_windows:
            if self.process:
                try:
                    self.process.stdin.write(data)
                    self.process.stdin.flush()
                    return len(data)
                except:
                    return None
        else:
            if self.master_fd:
                try:
                    return os.write(self.master_fd, data)
                except:
                    return None
        return None
        
    def close(self):
        """세션 종료"""
        if self.process:
            try:
                if self.is_windows:
                    self.process.terminate()
                else:
                    os.killpg(os.getpgid(self.process.pid), signal.SIGTERM)
            except:
                pass
            
        if self.master_fd and not self.is_windows:
            try:
                os.close(self.master_fd)
            except:
                pass

class RemoteSession:
    """원격 세션 관리 클래스"""
    def __init__(self, client_socket, addr):
        self.client = client_socket
        self.addr = addr
        self.pty = PtyHandler()
        self.running = True
        self.shell_mode = False
        
    def start(self):
        """세션 시작"""
        thread = threading.Thread(target=self.handle_client)
        thread.daemon = True
        thread.start()
        
    def handle_client(self):
        """클라이언트 요청 처리"""
        try:
            while self.running:
                data = self.receive_data()
                if not data:
                    break
                    
                command = json.loads(data)
                cmd_type = command.get('type', '')
                
                if cmd_type == 'shell' and not self.shell_mode:
                    self.start_shell_mode()
                elif self.shell_mode:
                    self.handle_shell_input(command)
                else:
                    self.handle_command(command)
                    
        except Exception as e:
            print(f"클라이언트 처리 중 오류: {str(e)}")
        finally:
            self.close()
            
    def start_shell_mode(self):
        """셸 모드 시작"""
        self.shell_mode = True
        if self.pty.create() and self.pty.spawn():
            # 입출력 스레드 시작
            output_thread = threading.Thread(target=self.handle_shell_output)
            output_thread.daemon = True
            output_thread.start()
            
            self.send_data({
                'type': 'shell',
                'status': 'started'
            })
        else:
            self.send_data({
                'type': 'error',
                'message': '셸 시작 실패'
            })
            self.shell_mode = False
            
    def handle_shell_input(self, command):
        """셸 입력 처리"""
        if command.get('type') == 'input':
            self.pty.write(command['data'].encode())
        elif command.get('type') == 'resize':
            self.pty.resize(command['rows'], command['cols'])
            
    def handle_shell_output(self):
        """셸 출력 처리"""
        try:
            while self.shell_mode and self.running:
                if not self.is_windows:
                    readable, _, _ = select.select([self.pty.master_fd], [], [], 0.1)
                    if self.pty.master_fd in readable:
                        data = self.pty.read(4096)
                        if data:
                            self.send_data({
                                'type': 'output',
                                'data': data.decode('utf-8', errors='replace')
                            })
                else:
                    data = self.pty.read(4096)
                    if data:
                        self.send_data({
                            'type': 'output',
                            'data': data.decode('utf-8', errors='replace')
                        })
                    time.sleep(0.01)
        except:
            self.shell_mode = False
            
    def handle_command(self, command):
        """일반 명령어 처리"""
        cmd_type = command.get('type', '')
        if cmd_type == 'exec':
            self.handle_exec(command)
        elif cmd_type == 'upload':
            self.handle_upload(command)
        elif cmd_type == 'download':
            self.handle_download(command)
            
    def handle_exec(self, command):
        """명령어 실행"""
        try:
            cmd = command.get('command', '')
            process = subprocess.Popen(
                cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            stdout, stderr = process.communicate()
            
            self.send_data({
                'type': 'exec_result',
                'stdout': stdout,
                'stderr': stderr,
                'code': process.returncode
            })
        except Exception as e:
            self.send_data({
                'type': 'error',
                'message': str(e)
            })
            
    def handle_upload(self, command):
        """파일 업로드 처리"""
        try:
            filename = command.get('filename', '')
            content = base64.b64decode(command.get('content', ''))
            
            with open(filename, 'wb') as f:
                f.write(content)
                
            self.send_data({
                'type': 'upload_result',
                'status': 'success'
            })
        except Exception as e:
            self.send_data({
                'type': 'error',
                'message': str(e)
            })
            
    def handle_download(self, command):
        """파일 다운로드 처리"""
        try:
            filename = command.get('filename', '')
            
            with open(filename, 'rb') as f:
                content = base64.b64encode(f.read()).decode()
                
            self.send_data({
                'type': 'download_result',
                'filename': filename,
                'content': content
            })
        except Exception as e:
            self.send_data({
                'type': 'error',
                'message': str(e)
            })
            
    def send_data(self, data):
        """데이터 전송"""
        try:
            json_data = json.dumps(data)
            size = len(json_data)
            self.client.sendall(f"{size:08d}".encode())
            self.client.sendall(json_data.encode())
        except:
            self.running = False
            
    def receive_data(self):
        """데이터 수신"""
        try:
            size_data = self.client.recv(8)
            if not size_data:
                return None
                
            size = int(size_data.decode())
            data = ""
            
            while len(data) < size:
                chunk = self.client.recv(min(size - len(data), 4096)).decode()
                if not chunk:
                    return None
                data += chunk
                
            return data
        except:
            return None
            
    def close(self):
        """세션 종료"""
        self.running = False
        self.shell_mode = False
        self.pty.close()
        try:
            self.client.close()
        except:
            pass

class RemoteServer:
    """서버 클래스"""
    def __init__(self, host='0.0.0.0', port=5000):
        self.host = host
        self.port = port
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.running = True

    def start(self):
        """서버 시작"""
        try:
            self.server.bind((self.host, self.port))
            self.server.listen(5)
            print(f"서버가 {self.host}:{self.port}에서 실행 중입니다.")
            
            while self.running:
                try:
                    client, addr = self.server.accept()
                    print(f"클라이언트 연결됨: {addr[0]}:{addr[1]}")
                    client_thread = threading.Thread(target=self.handle_client, args=(client, addr))
                    client_thread.daemon = True
                    client_thread.start()
                except socket.timeout:
                    continue
                    
        except Exception as e:
            print(f"서버 오류: {str(e)}")
        finally:
            self.cleanup()

    def handle_client(self, client_socket, addr):
        """클라이언트 요청 처리"""
        try:
            while self.running:
                try:
                    # 데이터 크기 수신
                    size_data = client_socket.recv(8)
                    if not size_data:
                        break
                    
                    size = int(size_data.decode())
                    data = ""
                    
                    # 데이터 수신
                    while len(data) < size:
                        chunk = client_socket.recv(min(size - len(data), 4096)).decode()
                        if not chunk:
                            break
                        data += chunk
                    
                    if not data:
                        break
                    
                    # 명령어 처리
                    command = json.loads(data)
                    command_type = command.get('type')
                    
                    print(f"명령어 수신: {command_type}")
                    
                    if command_type == 'upload':
                        self.handle_upload(client_socket, command)
                    elif command_type == 'download':
                        self.handle_download(client_socket, command)
                    elif command_type == 'command':
                        # 일반 명령어 실행
                        cmd = command.get('data', '')
                        print(f"명령어 실행: {cmd}")
                        output = self.execute_command(cmd)
                        self.send_response(client_socket, {
                            "status": "success",
                            "output": output
                        })
                    
                except json.JSONDecodeError as e:
                    print(f"잘못된 명령어 형식: {str(e)}")
                    self.send_response(client_socket, {
                        "status": "error",
                        "message": f"잘못된 명령어 형식: {str(e)}"
                    })
                    
        except Exception as e:
            print(f"클라이언트 처리 중 오류 발생: {str(e)}")
        finally:
            print(f"클라이언트 연결 종료: {addr[0]}:{addr[1]}")
            client_socket.close()

    def execute_command(self, command):
        """명령어 실행"""
        try:
            process = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            stdout, stderr = process.communicate()
            return stdout if stdout else stderr
        except Exception as e:
            return f"명령어 실행 오류: {str(e)}"

    def send_response(self, client_socket, response):
        """응답 전송"""
        try:
            json_data = json.dumps(response)
            size = len(json_data)
            client_socket.sendall(f"{size:08d}".encode())
            client_socket.sendall(json_data.encode())
        except Exception as e:
            print(f"응답 전송 실패: {str(e)}")

    def handle_upload(self, client_socket, data):
        """파일 업로드 처리"""
        try:
            filename = data.get('filename')
            content = data.get('content')
            chunk_info = data.get('chunk_info', {})
            
            print(f"파일 업로드 요청: {filename}")
            
            # 파일 쓰기 모드 설정
            mode = 'ab' if chunk_info.get('append_mode') else 'wb'
            
            # 파일 저장
            with open(filename, mode) as f:
                file_content = base64.b64decode(content)
                f.write(file_content)
            
            # 응답 전송
            response = {"status": "success", "message": "파일 업로드 성공"}
            if chunk_info.get('is_last', True):
                print(f"파일 업로드 완료: {filename}")
            
            self.send_response(client_socket, response)
            
        except Exception as e:
            print(f"파일 업로드 실패: {filename} - {str(e)}")
            self.send_response(client_socket, {
                "status": "error",
                "message": f"파일 업로드 실패: {str(e)}"
            })

    def handle_download(self, client_socket, data):
        """파일 다운로드 처리"""
        try:
            filename = data.get('filename')
            print(f"파일 다운로드 요청: {filename}")
            
            if not os.path.exists(filename):
                raise FileNotFoundError("파일을 찾을 수 없습니다")
            
            file_size = os.path.getsize(filename)
            print(f"파일 크기: {file_size:,} 바이트")
            
            with open(filename, 'rb') as f:
                content = base64.b64encode(f.read()).decode('utf-8')
            
            print(f"파일 다운로드 완료: {filename}")
            self.send_response(client_socket, {
                "status": "success",
                "content": content,
                "file_size": file_size
            })
            
        except Exception as e:
            print(f"파일 다운로드 실패: {filename} - {str(e)}")
            self.send_response(client_socket, {
                "status": "error",
                "message": f"파일 다운로드 실패: {str(e)}"
            })

    def cleanup(self):
        """자원 정리"""
        self.running = False
        
        try:
            self.server.close()
        except:
            pass

class RemoteClient:
    """클라이언트 클래스"""
    def __init__(self, host='localhost', port=5000):
        self.host = host
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)  # 연결 유지
        self.running = False
        self.command_handlers = {
            'upload': self.handle_upload,
            'download': self.handle_download,
            'help': self.show_help,
            'exit': self.handle_exit
        }
        
    def get_command(self):
        """사용자 입력을 직접 처리"""
        current_path = self.get_current_path()
        print(f"{current_path}> ", end='', flush=True)
        
        command = []
        while True:
            if os.name == 'nt':  # Windows
                if msvcrt.kbhit():
                    char = msvcrt.getch()
                    if char == b'\r':  # Enter
                        print()  # 새 줄
                        break
                    elif char == b'\x03':  # Ctrl+C
                        raise KeyboardInterrupt
                    elif char == b'\x08':  # Backspace
                        if command:
                            command.pop()
                            print('\b \b', end='', flush=True)
                    else:
                        try:
                            char_decoded = char.decode('utf-8')
                            command.append(char_decoded)
                            print(char_decoded, end='', flush=True)
                        except:
                            pass
            else:  # Unix/Linux
                try:
                    # 터미널 설정 저장
                    fd = sys.stdin.fileno()
                    old_settings = termios.tcgetattr(fd)
                    try:
                        # raw 모드로 변경
                        tty.setraw(fd)
                        char = sys.stdin.read(1)
                        if char == '\n' or char == '\r':  # Enter
                            print()
                            break
                        elif char == '\x03':  # Ctrl+C
                            raise KeyboardInterrupt
                        elif char == '\x7f':  # Backspace
                            if command:
                                command.pop()
                                print('\b \b', end='', flush=True)
                        else:
                            command.append(char)
                            print(char, end='', flush=True)
                    finally:
                        # 터미널 설정 복구
                        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
                except termios.error:
                    # 터미널이 아닌 경우 일반 입력 사용
                    line = input()
                    return line.strip()
        
        return ''.join(command).strip()

    def connect(self):
        try:
            self.socket.connect((self.host, self.port))
            print(f"서버 {self.host}:{self.port}에 연결되었습니다.")
            print("원격 명령 프롬프트에 오신 것을 환영합니다. 종료하려면 'exit'를 입력하세요.")
            
            while True:
                try:
                    command = self.get_command()
                    
                    if not command:
                        continue
                    
                    # 내부 명령어 처리
                    if command == "exit":
                        break
                    elif command == "help":
                        self.show_help()
                    elif command.startswith("upload "):
                        self.handle_upload(command[7:])
                    elif command.startswith("download "):
                        self.handle_download(command[9:])
                    else:
                        # 일반 명령어를 서버로 전송
                        self.send_and_receive({
                            "type": "command",
                            "data": command
                        })
                    
                except socket.timeout:
                    print("서버 응답 시간 초과")
                except KeyboardInterrupt:
                    print("\n프로그램을 종료합니다...")
                    break
                except Exception as e:
                    print(f"명령어 실행 중 오류 발생: {str(e)}")
                    break
                    
        except Exception as e:
            print(f"연결 오류: {str(e)}")
        finally:
            self.socket.close()

    def handle_exit(self, _):
        """종료 처리"""
        return False

    def show_help(self, _=None):
        """도움말 표시"""
        print("\n사용 가능한 명령어:")
        print("1. 파일 전송")
        print("  - upload <로컬파일> <원격파일>  : 파일 업로드")
        print("  - download <원격파일> <로컬파일>  : 파일 다운로드")
        print("\n2. 시스템 명령어")
        print("  - 모든 일반 시스템 명령어 사용 가능")
        print("\n3. 기타")
        print("  - help  : 이 도움말 보기")
        print("  - exit  : 프로그램 종료\n")
        return True

    def handle_upload(self, args):
        """파일 업로드 처리"""
        try:
            parts = args.split()
            if len(parts) != 2:
                print("사용법: upload <로컬파일> <원격파일>")
                return True
            
            local_file = parts[0]
            remote_file = parts[1]
            
            if not os.path.exists(local_file):
                print("로컬 파일을 찾을 수 없습니다.")
                return True
            
            file_size = os.path.getsize(local_file)
            if file_size == 0:
                print("빈 파일은 전송할 수 없습니다.")
                return True
                
            print(f"파일 크기: {file_size:,} 바이트", end='\r', flush=True)
            
            # 파일을 청크 단위로 읽어서 전송
            chunk_size = 1024 * 1024  # 1MB
            uploaded_size = 0
            
            with open(local_file, 'rb') as f:
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                        
                    content = base64.b64encode(chunk).decode('utf-8')
                    command_data = {
                        "type": "upload",
                        "filename": remote_file,
                        "content": content,
                        "chunk_info": {
                            "is_last": len(chunk) < chunk_size,
                            "append_mode": uploaded_size > 0
                        }
                    }
                    
                    response = self.send_and_receive(command_data)
                    if response.get("status") != "success":
                        raise Exception(response.get("message", "업로드 실패"))
                    
                    uploaded_size += len(chunk)
                    print(f"업로드 중: {uploaded_size:,}/{file_size:,} 바이트 ({uploaded_size/file_size*100:.1f}%)", 
                          end='\r', flush=True)
            
            print(f"\n파일 '{local_file}' 업로드 완료")
            
        except Exception as e:
            print(f"\n파일 업로드 실패: {str(e)}")
        return True

    def handle_download(self, args):
        """파일 다운로드 처리"""
        try:
            parts = args.split()
            if len(parts) != 2:
                print("사용법: download <원격파일> <로컬파일>")
                return True
            
            remote_file = parts[0]
            local_file = parts[1]
            
            command_data = {
                "type": "download",
                "filename": remote_file
            }
            
            response = self.send_and_receive(command_data)
            
            if response.get("status") == "success":
                content = base64.b64decode(response.get("content"))
                with open(local_file, 'wb') as f:
                    f.write(content)
                print(f"파일 '{local_file}' 다운로드 완료")
            else:
                print(f"다운로드 실패: {response.get('message')}")
                
        except Exception as e:
            print(f"파일 다운로드 실패: {str(e)}")
            if os.path.exists(local_file):
                os.remove(local_file)  # 실패한 경우 불완전한 파일 삭제
        return True

    def send_and_receive(self, command_data):
        """데이터 전송 및 수신"""
        try:
            # 데이터 전송
            json_data = json.dumps(command_data)
            size = len(json_data)
            self.socket.sendall(f"{size:08d}".encode())
            self.socket.sendall(json_data.encode())
            
            # 응답 수신
            size_data = self.socket.recv(8)
            if not size_data:
                raise ConnectionError("서버와의 연결이 끊어졌습니다.")
            
            size = int(size_data.decode())
            data = ""
            
            while len(data) < size:
                chunk = self.socket.recv(min(size - len(data), 4096)).decode()
                if not chunk:
                    raise ConnectionError("서버와의 연결이 끊어졌습니다.")
                data += chunk
            
            response = json.loads(data)
            if response.get("status") == "success":
                if "output" in response:
                    print(response["output"], end="")
            else:
                print(f"오류: {response.get('message', '알 수 없는 오류')}")
            
            return response
            
        except json.JSONDecodeError:
            raise Exception("서버로부터 잘못된 응답을 받았습니다.")
        except socket.timeout:
            raise Exception("서버 응답 시간이 초과되었습니다.")
        except ConnectionError as e:
            raise Exception(str(e))
        except Exception as e:
            raise Exception(f"통신 오류: {str(e)}")

    def get_current_path(self):
        """현재 경로 가져오기"""
        if platform.system() != 'Windows':
            return os.getcwd()
        else:
            return os.path.dirname(os.path.abspath(__file__))

def is_valid_host(host):
    """호스트명이나 IP 주소의 유효성 검사"""
    try:
        # 호스트명이나 IP 주소 확인
        socket.gethostbyname(host)
        return True
    except socket.gaierror:
        return False

def main():
    """메인 함수"""
    if len(sys.argv) > 1:
        # IP 주소나 'client' 파라미터로 클라이언트 모드 실행
        if sys.argv[1] == 'client':
            # 기존 client 명령어 지원
            print("클라이언트 모드로 시작합니다...")
            while True:
                host = input("서버 IP 주소 (기본: localhost): ").strip() or 'localhost'
                if is_valid_host(host):
                    break
                print(f"잘못된 IP 주소 또는 호스트명입니다: {host}")
            
            client = RemoteClient(host=host)
            try:
                client.connect()
            except ConnectionRefusedError:
                print(f"서버 연결 실패: {host}:{client.port}에서 연결이 거부되었습니다.")
            except Exception as e:
                print(f"서버 연결 실패: {str(e)}")
        else:
            # IP 주소를 직접 파라미터로 받은 경우
            host = sys.argv[1]
            if not is_valid_host(host):
                print(f"잘못된 IP 주소 또는 호스트명입니다: {host}")
                print("사용법:")
                print("  서버 모드: python remotecmd.py")
                print("  클라이언트 모드: python remotecmd.py <IP주소 또는 호스트명>")
                return
            
            print(f"클라이언트 모드로 시작합니다... (서버: {host})")
            client = RemoteClient(host=host)
            try:
                client.connect()
            except ConnectionRefusedError:
                print(f"서버 연결 실패: {host}:{client.port}에서 연결이 거부되었습니다.")
            except Exception as e:
                print(f"서버 연결 실패: {str(e)}")
    else:
        # 파라미터가 없으면 서버 모드로 실행
        print("서버 모드로 시작합니다...")
        server = RemoteServer()
        try:
            server.start()
        except KeyboardInterrupt:
            print("\n서버를 종료합니다...")
            server.shutdown()

if __name__ == "__main__":
    main()
