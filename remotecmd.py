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
import msvcrt  # Windows용

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
        self.running = True
        self.sessions = []
        
    def start(self):
        """서버 시작"""
        try:
            self.server.bind((self.host, self.port))
            self.server.listen(5)
            self.server.settimeout(1)
            
            print(f"서버가 {self.host}:{self.port}에서 실행 중입니다.")
            print("사용 가능한 명령어:")
            print("- shutdown: 서버 종료")
            print("- list: 연결된 클라이언트 목록")
            print("- kill <세션ID>: 특정 클라이언트 연결 종료")
            
            shutdown_thread = threading.Thread(target=self.check_shutdown)
            shutdown_thread.daemon = True
            shutdown_thread.start()
            
            while self.running:
                try:
                    client, addr = self.server.accept()
                    print(f"클라이언트 {addr} 연결됨")
                    
                    session = RemoteSession(client, addr)
                    self.sessions.append(session)
                    session.start()
                except socket.timeout:
                    continue
                    
        except KeyboardInterrupt:
            print("\n서버를 종료합니다...")
        finally:
            self.cleanup()
            
    def check_shutdown(self):
        """서버 명령어 처리"""
        while self.running:
            try:
                cmd = input().strip().lower()
                if cmd == 'shutdown':
                    print("서버를 종료합니다...")
                    self.running = False
                elif cmd == 'list':
                    self.list_sessions()
                elif cmd.startswith('kill '):
                    self.kill_session(cmd[5:])
            except:
                pass
                
    def list_sessions(self):
        """연결된 클라이언트 목록 출력"""
        print("\n연결된 클라이언트 목록:")
        for i, session in enumerate(self.sessions):
            if session.running:
                print(f"{i}: {session.addr[0]}:{session.addr[1]}")
        print()
                
    def kill_session(self, session_id):
        """특정 세션 종료"""
        try:
            idx = int(session_id)
            if 0 <= idx < len(self.sessions):
                session = self.sessions[idx]
                if session.running:
                    session.close()
                    print(f"세션 {idx} ({session.addr[0]}:{session.addr[1]}) 종료됨")
                else:
                    print("이미 종료된 세션입니다.")
            else:
                print("잘못된 세션 ID입니다.")
        except ValueError:
            print("올바른 세션 ID를 입력하세요.")
                
    def cleanup(self):
        """자원 정리"""
        self.running = False
        
        for session in self.sessions:
            session.close()
            
        try:
            self.server.close()
        except:
            pass

class RemoteClient:
    """클라이언트 클래스"""
    def __init__(self, host='localhost', port=5000):
        self.host = host
        self.port = port
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.running = False
        self.command_handlers = {
            'put': self.handle_upload,
            'get': self.handle_download,
            'help': self.show_help,
            'exit': self.handle_exit
        }
        
    def get_command(self):
        """사용자 입력을 운영체제별로 처리"""
        current_path = self.get_current_path()
        if os.name == 'nt':  # Windows
            print(f"{current_path}> ", end='', flush=True)
            command = []
            while True:
                import msvcrt
                if msvcrt.kbhit():
                    char = msvcrt.getch()
                    if char == b'\r':  # Enter
                        print()
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
            return ''.join(command).strip()
        else:  # Linux/Unix
            return input(f"{current_path}> ").strip()

    def connect(self):
        try:
            self.client.connect((self.host, self.port))
            print(f"서버 {self.host}:{self.port}에 연결되었습니다.")
            print("원격 명령 프롬프트에 오신 것을 환영합니다. 종료하려면 'exit'를 입력하세요.")
            
            while True:
                command = self.get_command()
                
                if command.lower() == 'exit':
                    break
                    
                if command.strip() == '':
                    continue
                    
                self.client.send(command.encode())
                response = self.client.recv(4096).decode()
                print(response.rstrip())
                
        except Exception as e:
            print(f"에러 발생: {str(e)}")
        finally:
            self.client.close()

    def handle_exit(self, _):
        """종료 처리"""
        return False

    def show_help(self, _=None):
        """도움말 표시"""
        print("\n사용 가능한 명령어:")
        print("1. 파일 전송")
        print("  - put <로컬파일> <원격파일>  : 파일 업로드")
        print("  - get <원격파일> <로컬파일>  : 파일 다운로드")
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
                print("사용법: put <로컬파일> <원격파일>")
                return True
            
            local_file = parts[0]
            remote_file = parts[1]
            
            if not os.path.exists(local_file):
                print("로컬 파일을 찾을 수 없습니다.")
                return True
            
            file_size = os.path.getsize(local_file)
            print(f"파일 크기: {file_size:,} 바이트")
            
            with open(local_file, 'rb') as f:
                content = base64.b64encode(f.read()).decode('utf-8')
            
            command_data = {
                "type": "upload",
                "filename": remote_file,
                "content": content
            }
            
            response = self.send_and_receive(command_data)
            if response.get("status") == "success":
                print(f"파일 '{local_file}' 업로드 완료")
            else:
                print(f"업로드 실패: {response.get('message')}")
            
        except Exception as e:
            print(f"파일 업로드 실패: {str(e)}")
        return True

    def handle_download(self, args):
        """파일 다운로드 처리"""
        try:
            parts = args.split()
            if len(parts) != 2:
                print("사용법: get <원격파일> <로컬파일>")
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
        return True

    def send_and_receive(self, command_data):
        """데이터 전송 및 수신"""
        try:
            json_data = json.dumps(command_data)
            size = len(json_data)
            self.client.sendall(f"{size:08d}".encode())
            self.client.sendall(json_data.encode())
            
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
                
            return json.loads(data)
        except:
            return None

    def get_current_path(self):
        """현재 경로 가져오기"""
        if platform.system() != 'Windows':
            return os.getcwd()
        else:
            return os.path.dirname(os.path.abspath(__file__))

def main():
    """메인 함수"""
    if len(sys.argv) > 1:
        # 클라이언트 모드
        if sys.argv[1] == 'client':
            print("클라이언트 모드로 시작합니다...")
            host = input("서버 IP 주소 (기본: localhost): ").strip() or 'localhost'
            client = RemoteClient(host=host)
            client.connect()
    else:
        # 서버 모드 (기본)
        print("서버 모드로 시작합니다...")
        server = RemoteServer()
        try:
            server.start()
        except KeyboardInterrupt:
            print("\n서버를 종료합니다...")
            server.shutdown()

if __name__ == "__main__":
    main()
