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
import errno

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
        self.buffer = b''
        self.interactive_commands = {'cat', 'nano', 'vi', 'vim', 'less', 'more', 'tail -f'}
        
    def create(self):
        """PTY 생성"""
        if not self.is_windows:
            self.master_fd, self.slave_fd = pty.openpty()
            # PTY 설정
            attr = termios.tcgetattr(self.slave_fd)
            attr[3] = attr[3] & ~termios.ECHO  # Echo 끄기
            attr[0] = attr[0] | termios.ICRNL   # CR -> NL 변환
            attr[1] = attr[1] | termios.ONLCR   # NL -> CR-NL 변환
            termios.tcsetattr(self.slave_fd, termios.TCSANOW, attr)
            
            # 터미널 크기 설정
            rows, cols = TerminalSize.get_terminal_size()
            self.resize(rows, cols)
            return True
        return False
        
    def spawn(self, shell=None):
        """셸 프로세스 생성"""
        if not shell:
            shell = 'cmd.exe' if self.is_windows else '/bin/bash'
            
        if self.is_windows:
            # Windows에서는 subprocess를 통해 실행
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            
            self.process = subprocess.Popen(
                shell,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=True,
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
                startupinfo=startupinfo,
                bufsize=0
            )
            return True
        else:
            env = {
                'TERM': 'xterm-256color',
                'PATH': os.environ.get('PATH', ''),
                'HOME': os.environ.get('HOME', ''),
                'SHELL': shell,
                'LANG': os.environ.get('LANG', 'en_US.UTF-8')
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
            
    def read(self, size=1024):
        """데이터 읽기"""
        if self.is_windows:
            if self.process:
                try:
                    # Windows에서는 stdout과 stderr을 모두 확인
                    output = b''
                    
                    # stdout 확인
                    if self.process.stdout:
                        try:
                            data = self.process.stdout.read1(size)
                            if data:
                                output += data
                        except (IOError, OSError):
                            pass
                            
                    # stderr 확인
                    if self.process.stderr:
                        try:
                            data = self.process.stderr.read1(size)
                            if data:
                                output += data
                        except (IOError, OSError):
                            pass
                            
                    return output if output else None
                except:
                    return None
        else:
            if self.master_fd:
                try:
                    # Unix/Linux에서는 master_fd에서 읽기
                    return os.read(self.master_fd, size)
                except (IOError, OSError) as e:
                    if e.errno != errno.EAGAIN:
                        raise
                    return None
        return None
        
    def write(self, data):
        """데이터 쓰기"""
        if isinstance(data, str):
            data = data.encode()
            
        if self.is_windows:
            if self.process and self.process.stdin:
                try:
                    # Windows에서는 stdin에 직접 쓰기
                    self.process.stdin.write(data)
                    self.process.stdin.flush()
                    return len(data)
                except (IOError, OSError):
                    return None
        else:
            if self.master_fd:
                try:
                    # Unix/Linux에서는 master_fd에 쓰기
                    return os.write(self.master_fd, data)
                except (IOError, OSError) as e:
                    if e.errno != errno.EAGAIN:
                        raise
                    return None
        return None

    def handle_control_chars(self, data):
        """컨트롤 문자 처리"""
        # 컨트롤 문자 처리 로직
        control_chars = {
            b'\x03': self.handle_ctrl_c,  # Ctrl+C
            b'\x04': self.handle_ctrl_d,  # Ctrl+D
            b'\x1a': self.handle_ctrl_z,  # Ctrl+Z
            b'\x1b': lambda: b'\x1b',     # ESC
            b'\r': lambda: b'\r\n' if not self.is_windows else b'\r\n'  # Enter
        }
        
        if data in control_chars:
            return control_chars[data]()
        return data
    
    def handle_ctrl_c(self):
        """Ctrl+C 처리"""
        if self.is_windows:
            self.process.send_signal(signal.CTRL_C_EVENT)
        else:
            os.kill(self.process.pid, signal.SIGINT)
        return b'^C\n'
    
    def handle_ctrl_d(self):
        """Ctrl+D 처리"""
        if not self.is_windows:
            return b'\x04'
        return b''
    
    def handle_ctrl_z(self):
        """Ctrl+Z 처리"""
        if self.is_windows:
            self.process.send_signal(signal.CTRL_BREAK_EVENT)
        else:
            os.kill(self.process.pid, signal.SIGTSTP)
        return b'^Z\n'
        
    def resize(self, rows, cols):
        """터미널 크기 조정"""
        if not self.is_windows and self.master_fd:
            winsize = struct.pack('HHHH', rows, cols, 0, 0)
            try:
                fcntl.ioctl(self.master_fd, termios.TIOCSWINSZ, winsize)
            except (IOError, OSError) as e:
                if e.errno != errno.EINVAL:
                    raise
            
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
            data = command['data'].encode() if isinstance(command['data'], str) else command['data']
            # 컨트롤 문자 처리
            processed_data = self.pty.handle_control_chars(data)
            if processed_data:
                self.pty.write(processed_data)
                # 대화형 명령어 처리를 위한 즉시 출력
                if self.pty.is_windows:
                    time.sleep(0.1)  # Windows에서 출력 동기화를 위한 짧은 대기
                    output = self.pty.read(4096)
                    if output:
                        try:
                            decoded_output = output.decode('utf-8', errors='replace')
                            self.send_data({
                                'type': 'output',
                                'data': decoded_output
                            })
                        except UnicodeDecodeError:
                            self.send_data({
                                'type': 'output',
                                'data': str(output)
                            })
        elif command.get('type') == 'resize':
            # 터미널 크기 조정
            rows = command.get('rows', 24)
            cols = command.get('cols', 80)
            self.pty.resize(rows, cols)
            
    def handle_shell_output(self):
        """셸 출력 처리"""
        try:
            while self.shell_mode and self.running:
                if not self.pty.is_windows:
                    try:
                        readable, _, _ = select.select([self.pty.master_fd], [], [], 0.1)
                        if self.pty.master_fd in readable:
                            data = self.pty.read(4096)
                            if data:
                                try:
                                    decoded_data = data.decode('utf-8', errors='replace')
                                    self.send_data({
                                        'type': 'output',
                                        'data': decoded_data
                                    })
                                except UnicodeDecodeError:
                                    self.send_data({
                                        'type': 'output',
                                        'data': str(data)
                                    })
                    except (select.error, IOError) as e:
                        if e.args[0] != errno.EINTR:  # EINTR 오류 무시
                            raise
                else:
                    data = self.pty.read(4096)
                    if data:
                        try:
                            decoded_data = data.decode('utf-8', errors='replace')
                            self.send_data({
                                'type': 'output',
                                'data': decoded_data
                            })
                        except UnicodeDecodeError:
                            self.send_data({
                                'type': 'output',
                                'data': str(data)
                            })
                    time.sleep(0.01)
        except Exception as e:
            print(f"셸 출력 처리 중 오류 발생: {str(e)}")
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
            self.server.settimeout(1)  # 타임아웃 설정
            print(f"서버가 {self.host}:{self.port}에서 실행 중입니다.")
            print("사용 가능한 명령어:")
            print("- shutdown: 서버 종료")
            
            # 서버 명령어 처리를 위한 스레드 시작
            command_thread = threading.Thread(target=self.handle_server_commands)
            command_thread.daemon = True
            command_thread.start()
            
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

    def handle_server_commands(self):
        """서버 명령어 처리"""
        while self.running:
            try:
                command = input().strip().lower()
                if command == 'shutdown':
                    print("서버를 종료합니다...")
                    self.running = False
                    break
            except:
                pass

    def cleanup(self):
        """서버 자원 정리"""
        self.running = False
        try:
            # 모든 클라이언트 연결 종료
            for client in self.get_all_clients():
                try:
                    client.close()
                except:
                    pass
            
            # 서버 소켓 종료
            self.server.close()
            print("서버가 종료되었습니다.")
        except:
            pass

    def get_all_clients(self):
        """연결된 모든 클라이언트 소켓 반환"""
        clients = []
        for thread in threading.enumerate():
            if thread.name.startswith('Thread-'):
                if hasattr(thread, '_args'):
                    if len(thread._args) > 0 and isinstance(thread._args[0], socket.socket):
                        clients.append(thread._args[0])
        return clients

    def shutdown(self):
        """서버 종료"""
        self.running = False

    def handle_client(self, client_socket, addr):
        """클라이언트 요청 처리"""
        try:
            # 초기 프롬프트 전송
            self.send_prompt(client_socket)
            
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
                            "output": output,
                            "prompt": self.get_prompt()
                        })
                    
                except json.JSONDecodeError as e:
                    print(f"잘못된 명령어 형식: {str(e)}")
                    self.send_response(client_socket, {
                        "status": "error",
                        "message": f"잘못된 명령어 형식: {str(e)}",
                        "prompt": self.get_prompt()
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

    def get_prompt(self):
        """현재 서버 프롬프트 반환"""
        return f"{os.getcwd()}>"

    def send_prompt(self, client_socket):
        """프롬프트 전송"""
        self.send_response(client_socket, {
            "status": "success",
            "prompt": self.get_prompt()
        })

class RemoteClient:
    """클라이언트 클래스"""
    def __init__(self, host='localhost', port=5000):
        self.host = host
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        self.running = False
        self.shell_mode = False
        self.old_terminal_settings = None
        self.command_handlers = {
            'upload': self.handle_upload,
            'download': self.handle_download,
            'help': self.show_help,
            'exit': self.handle_exit,
            'shell': self.start_shell_mode
        }

    def setup_terminal(self):
        """터미널을 raw 모드로 설정"""
        if os.name != 'nt':
            self.old_terminal_settings = termios.tcgetattr(sys.stdin.fileno())
            tty.setraw(sys.stdin.fileno())
        else:
            # Windows의 경우 가상 터미널 모드 설정
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-10), 0x0001 | 0x0002 | 0x0004)

    def restore_terminal(self):
        """터미널 설정 복원"""
        if os.name != 'nt' and self.old_terminal_settings:
            termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, self.old_terminal_settings)
        elif os.name == 'nt':
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-10), 0x0007)

    def start_shell_mode(self):
        """셸 모드 시작"""
        try:
            self.shell_mode = True
            self.setup_terminal()
            
            # 서버에 셸 모드 시작 요청
            self.send_and_receive({"type": "shell"})
            
            # 터미널 크기 전송
            self.send_terminal_size()
            
            # 입력 처리 스레드 시작
            input_thread = threading.Thread(target=self.handle_shell_input)
            input_thread.daemon = True
            input_thread.start()
            
            # 터미널 크기 변경 감지 스레드 시작
            resize_thread = threading.Thread(target=self.handle_terminal_resize)
            resize_thread.daemon = True
            resize_thread.start()
            
            # 출력 처리
            self.handle_shell_output()
            
        except Exception as e:
            print(f"\r\n셸 모드 시작 실패: {str(e)}")
        finally:
            self.shell_mode = False
            self.restore_terminal()

    def send_terminal_size(self):
        """터미널 크기 정보 전송"""
        try:
            rows, cols = TerminalSize.get_terminal_size()
            self.send_and_receive({
                "type": "resize",
                "rows": rows,
                "cols": cols
            })
        except Exception as e:
            print(f"\r\n터미널 크기 전송 실패: {str(e)}")

    def handle_terminal_resize(self):
        """터미널 크기 변경 감지 및 처리"""
        last_size = None
        try:
            while self.shell_mode:
                current_size = TerminalSize.get_terminal_size()
                if current_size != last_size:
                    last_size = current_size
                    rows, cols = current_size
                    self.send_and_receive({
                        "type": "resize",
                        "rows": rows,
                        "cols": cols
                    })
                time.sleep(0.5)  # 0.5초마다 크기 확인
        except Exception as e:
            print(f"\r\n터미널 크기 처리 오류: {str(e)}")

    def handle_shell_input(self):
        """셸 입력 처리"""
        try:
            while self.shell_mode:
                if os.name == 'nt':
                    if msvcrt.kbhit():
                        char = msvcrt.getch()
                        self.send_and_receive({
                            "type": "input",
                            "data": char.decode('utf-8', errors='ignore')
                        })
                else:
                    char = sys.stdin.read(1)
                    if char:
                        self.send_and_receive({
                            "type": "input",
                            "data": char
                        })
        except Exception as e:
            print(f"\r\n입력 처리 오류: {str(e)}")
            self.shell_mode = False

    def handle_shell_output(self):
        """셸 출력 처리"""
        try:
            while self.shell_mode:
                response = self.receive_response()
                if response.get("type") == "output":
                    sys.stdout.write(response["data"])
                    sys.stdout.flush()
                elif response.get("type") == "error":
                    print(f"\r\n오류: {response.get('message')}")
                    break
        except Exception as e:
            print(f"\r\n출력 처리 오류: {str(e)}")
            self.shell_mode = False

    def connect(self):
        try:
            self.socket.connect((self.host, self.port))
            print(f"서버 {self.host}:{self.port}에 연결되었습니다.")
            print("원격 명령 프롬프트에 오신 것을 환영합니다.")
            print("- 종료: exit")
            print("- 도움말: help")
            print("- 셸 모드: shell")
            print("- 로컬 명령어: !명령어 (예: !dir)")
            
            # 초기 프롬프트 수신
            response = self.receive_response()
            current_prompt = response.get("prompt", "")
            
            while True:
                try:
                    if not self.shell_mode:
                        command = input(current_prompt).strip()
                        
                        if not command:
                            continue
                        
                        # 내부 명령어 처리
                        if command == "exit":
                            break
                        elif command == "help":
                            self.show_help()
                        elif command == "shell":
                            self.start_shell_mode()
                        elif command.startswith("upload "):
                            self.handle_upload(command[7:])
                        elif command.startswith("download "):
                            self.handle_download(command[9:])
                        elif command.startswith("!"):  # 로컬 명령어 처리
                            self.execute_local_command(command[1:])
                        else:
                            # 일반 명령어를 서버로 전송
                            response = self.send_and_receive({
                                "type": "command",
                                "data": command
                            })
                            current_prompt = response.get("prompt", current_prompt)
                    
                except socket.timeout:
                    print("서버 응답 시간 초과")
                except KeyboardInterrupt:
                    if self.shell_mode:
                        # 셸 모드에서는 Ctrl+C를 서버로 전송
                        self.send_and_receive({
                            "type": "input",
                            "data": "\x03"
                        })
                    else:
                        print("\n프로그램을 종료합니다...")
                        break
                except Exception as e:
                    print(f"명령어 실행 중 오류 발생: {str(e)}")
                    if self.shell_mode:
                        self.shell_mode = False
                        self.restore_terminal()
                    break
                    
        except Exception as e:
            print(f"연결 오류: {str(e)}")
        finally:
            self.restore_terminal()
            self.socket.close()

    def execute_local_command(self, command):
        """로컬 명령어 실행"""
        try:
            process = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            stdout, stderr = process.communicate()
            
            if stdout:
                print(stdout, end='')
            if stderr:
                print(stderr, end='')
                
        except Exception as e:
            print(f"로컬 명령어 실행 실패: {str(e)}")

    def receive_response(self):
        """서버 응답 수신"""
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
        
        return json.loads(data)

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
        print("  - 원격 명령어: 직접 입력 (예: dir)")
        print("  - 로컬 명령어: ! 접두사 사용 (예: !dir)")
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
