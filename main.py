import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import sqlite3
from cryptography.fernet import Fernet
import socket
import struct
import os
import threading
import time
import sys
from tqdm import tqdm

class ChatApplication:
    def __init__(self, root):
        self.root = root
        self.root.title("FILE-CHAT")
        self.root.geometry("800x600")
        self.root.resizable(True, True)
        
        # 应用状态变量
        self.key = None
        self.cipher_suite = None
        self.ip_address = None
        self.mode = None
        self.running = True
        self.tcp_client_socket = None
        self.file_receiving = False
        self.file_sending = False
        
        # 创建数据库
        self.create_db()
        
        # 创建UI
        self.setup_ui()
        
        # 设置关闭事件处理
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
    
    def setup_ui(self):
        # 创建主框架
        self.main_frame = ttk.Frame(self.root, padding="10")
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # 设置区域
        self.setup_frame = ttk.LabelFrame(self.main_frame, text="设置", padding="10")
        self.setup_frame.pack(fill=tk.X, pady=(0, 10))
        
        # 密钥设置
        ttk.Label(self.setup_frame, text="密钥:").grid(row=0, column=0, sticky=tk.W)
        self.key_entry = ttk.Entry(self.setup_frame, width=50)
        self.key_entry.grid(row=0, column=1, padx=5)
        ttk.Button(self.setup_frame, text="生成密钥", command=self.generate_key).grid(row=0, column=2)
        
        # IP地址设置
        ttk.Label(self.setup_frame, text="对方IP地址:").grid(row=1, column=0, sticky=tk.W)
        self.ip_entry = ttk.Entry(self.setup_frame, width=50)
        self.ip_entry.grid(row=1, column=1, padx=5, pady=5)
        
        # 模式选择
        ttk.Label(self.setup_frame, text="通信模式:").grid(row=2, column=0, sticky=tk.W)
        self.mode_var = tk.StringVar()
        self.mode_combobox = ttk.Combobox(self.setup_frame, textvariable=self.mode_var, 
                                         values=["TCP", "UDP"], state="readonly", width=10)
        self.mode_combobox.grid(row=2, column=1, sticky=tk.W, padx=5)
        self.mode_combobox.current(0)
        
        # 操作按钮
        ttk.Button(self.setup_frame, text="启动", command=self.start_connection).grid(row=2, column=2, padx=5)
        ttk.Button(self.setup_frame, text="查看历史记录", command=self.show_history).grid(row=2, column=3, padx=5)
        
        # 聊天区域
        self.chat_frame = ttk.LabelFrame(self.main_frame, text="聊天", padding="10")
        self.chat_frame.pack(fill=tk.BOTH, expand=True)
        
        # 聊天记录显示
        self.chat_history = scrolledtext.ScrolledText(self.chat_frame, height=15, state=tk.DISABLED)
        self.chat_history.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # 消息输入区域
        self.input_frame = ttk.Frame(self.chat_frame)
        self.input_frame.pack(fill=tk.X)
        
        self.message_entry = ttk.Entry(self.input_frame)
        self.message_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        self.message_entry.bind("<Return>", self.send_message)
        
        # 按钮区域
        self.button_frame = ttk.Frame(self.input_frame)
        self.button_frame.pack(side=tk.RIGHT)
        
        ttk.Button(self.button_frame, text="发送", command=self.send_message).pack(side=tk.LEFT, padx=2)
        ttk.Button(self.button_frame, text="发送文件", command=self.send_file).pack(side=tk.LEFT, padx=2)
        ttk.Button(self.button_frame, text="帮助", command=self.show_help).pack(side=tk.LEFT, padx=2)
        
        # 状态栏
        self.status_var = tk.StringVar()
        self.status_var.set("就绪")
        self.status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
    
    def generate_key(self):
        key = Fernet.generate_key()
        self.key_entry.delete(0, tk.END)
        self.key_entry.insert(0, key.decode())
        messagebox.showinfo("密钥生成", f"已生成新密钥:\n{key.decode()}\n\n请确保双方使用相同的密钥!")
    
    def create_db(self):
        conn = sqlite3.connect('chat_records.db')
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS chat (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            message TEXT
                        )''')
        conn.commit()
        conn.close()
    
    def save_chat(self, message):
        if not self.cipher_suite:
            return
            
        conn = sqlite3.connect('chat_records.db')
        cursor = conn.cursor()
        encrypted_message = self.cipher_suite.encrypt(message.encode('utf-8'))
        cursor.execute("INSERT INTO chat (message) VALUES (?)", (encrypted_message,))
        conn.commit()
        conn.close()
    
    def get_chat_records(self):
        if not self.cipher_suite:
            return []
            
        conn = sqlite3.connect('chat_records.db')
        cursor = conn.cursor()
        cursor.execute("SELECT message FROM chat")
        records = cursor.fetchall()
        conn.close()
        
        decrypted_records = []
        for record in records:
            decrypted_message = self.cipher_suite.decrypt(record[0]).decode('utf-8')
            decrypted_records.append(decrypted_message)
        
        return decrypted_records
    
    def show_history(self):
        if not self.cipher_suite:
            messagebox.showerror("错误", "请先生成或输入密钥!")
            return
            
        records = self.get_chat_records()
        if not records:
            messagebox.showinfo("历史记录", "没有聊天记录")
            return
            
        history_window = tk.Toplevel(self.root)
        history_window.title("聊天历史记录")
        history_window.geometry("600x400")
        
        history_text = scrolledtext.ScrolledText(history_window, wrap=tk.WORD)
        history_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        for record in records:
            history_text.insert(tk.END, record + "\n")
        
        history_text.config(state=tk.DISABLED)
        
        ttk.Button(history_window, text="关闭", command=history_window.destroy).pack(pady=10)
    
    def start_connection(self):
        # 获取密钥
        key = self.key_entry.get().strip()
        if not key:
            messagebox.showerror("错误", "请输入密钥!")
            return
            
        try:
            self.key = key.encode()
            self.cipher_suite = Fernet(self.key)
        except Exception as e:
            messagebox.showerror("错误", f"无效的密钥: {str(e)}")
            return
            
        # 获取IP地址
        self.ip_address = self.ip_entry.get().strip()
        if not self.ip_address:
            messagebox.showerror("错误", "请输入对方IP地址!")
            return
            
        # 获取通信模式
        self.mode = self.mode_var.get()
        
        # 禁用设置区域
        for widget in self.setup_frame.winfo_children():
            widget.configure(state=tk.DISABLED)
        
        # 启动通信线程
        if self.mode == "TCP":
            self.status_var.set("启动TCP通信...")
            threading.Thread(target=self.start_tcp, daemon=True).start()
        else:  # UDP
            self.status_var.set("启动UDP通信...")
            threading.Thread(target=self.start_udp, daemon=True).start()
    
    def start_tcp(self):
        # 启动服务器线程
        threading.Thread(target=self.tcp_server, daemon=True).start()
        time.sleep(1)
        
        # 启动客户端线程
        threading.Thread(target=self.tcp_client, daemon=True).start()
    
    def start_udp(self):
        # 启动服务器线程
        threading.Thread(target=self.udp_server, daemon=True).start()
        time.sleep(1)
        
        # 启动客户端线程
        threading.Thread(target=self.udp_client, daemon=True).start()
    
    def tcp_server(self):
        self.status_var.set("TCP服务器启动中...")
        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.settimeout(1.0)  # 设置超时
            server_socket.bind(('0.0.0.0', 12345))
            server_socket.listen(1)
            self.status_var.set("TCP服务器已启动，等待连接...")
            
            while self.running:
                try:
                    client_socket, addr = server_socket.accept()
                    self.status_var.set(f"来自 {addr} 的连接")
                    
                    client_socket.settimeout(1.0)  # 设置超时
                    
                    while self.running:
                        try:
                            encrypted_message = client_socket.recv(1024)
                            if not encrypted_message:
                                continue
                            
                            try:
                                # 解密消息
                                message = self.cipher_suite.decrypt(encrypted_message).decode('utf-8')
                                self.display_message(f"来自 {addr}: {message}")
                                self.save_chat(f"来自 {addr}: {message}")
                                
                                if message == 'sendF':
                                    threading.Thread(target=self.receive_file, daemon=True).start()
                            except Exception as e:
                                self.status_var.set(f"解密错误: {str(e)}")
                        except socket.timeout:
                            continue
                        except Exception as e:
                            self.status_var.set(f"接收错误: {str(e)}")
                            break
                    
                    client_socket.close()
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        self.status_var.set(f"TCP服务器错误: {str(e)}")
        except Exception as e:
            if self.running:
                self.status_var.set(f"TCP服务器错误: {str(e)}")
    
    def tcp_client(self):
        self.status_var.set("尝试连接到TCP服务器...")
        try:
            self.tcp_client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.tcp_client_socket.settimeout(5.0)  # 设置连接超时
            self.tcp_client_socket.connect((self.ip_address, 12345))
            self.tcp_client_socket.settimeout(1.0)  # 设置后续超时
            self.status_var.set(f"已连接到 {self.ip_address}:12345")
        except socket.timeout:
            self.status_var.set("连接超时，请检查IP地址和网络")
        except Exception as e:
            self.status_var.set(f"TCP连接错误: {str(e)}")
    
    def udp_server(self):
        self.status_var.set("UDP服务器启动中...")
        try:
            udp_addr = ('0.0.0.0', 9999)
            udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp_socket.settimeout(1.0)  # 设置超时
            udp_socket.bind(udp_addr)
            self.status_var.set("UDP服务器已启动")
            
            while self.running:
                try:
                    recv_data = udp_socket.recvfrom(1024)
                    if not recv_data or not recv_data[0]:
                        continue
                    
                    try:
                        # 解密消息
                        encrypted_message = recv_data[0]
                        message = self.cipher_suite.decrypt(encrypted_message).decode('utf-8')
                        addr = recv_data[1]
                        
                        self.display_message(f"[来自 {addr[0]}:{addr[1]}]: {message}")
                        self.save_chat(f"[来自 {addr[0]}:{addr[1]}]: {message}")
                        
                        if message == 'sendF':
                            threading.Thread(target=self.receive_file, daemon=True).start()
                    except Exception as e:
                        self.status_var.set(f"解密错误: {str(e)}")
                except socket.timeout:
                    continue
                except Exception as e:
                    self.status_var.set(f"接收错误: {str(e)}")
        except Exception as e:
            if self.running:
                self.status_var.set(f"UDP服务器错误: {str(e)}")
    
    def udp_client(self):
        self.status_var.set("UDP客户端已准备就绪")
        # 客户端发送功能由用户触发
    
    def send_message(self, event=None):
        if not self.cipher_suite:
            messagebox.showerror("错误", "请先启动连接!")
            return
            
        message = self.message_entry.get().strip()
        if not message:
            return
            
        self.message_entry.delete(0, tk.END)
        
        # 显示自己的消息
        self.display_message(f"我: {message}")
        self.save_chat(f"我: {message}")
        
        # 加密并发送消息
        encrypted_message = self.cipher_suite.encrypt(message.encode('utf-8'))
        
        if self.mode == "TCP":
            try:
                if self.tcp_client_socket:
                    self.tcp_client_socket.sendall(encrypted_message)
                else:
                    self.status_var.set("TCP连接未建立")
            except Exception as e:
                self.status_var.set(f"发送错误: {str(e)}")
        else:  # UDP
            try:
                udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                udp_addr = (self.ip_address, 9999)
                udp_socket.sendto(encrypted_message, udp_addr)
                udp_socket.close()
            except Exception as e:
                self.status_var.set(f"发送错误: {str(e)}")
        
        # 如果是发送文件指令
        if message == 'sendF':
            threading.Thread(target=self.send_file, daemon=True).start()
    
    def send_file(self):
        if self.file_sending:
            self.status_var.set("当前已有文件正在发送，请等待...")
            return
            
        self.file_sending = True
        try:
            self.send_message_async('sendF')
            self.status_var.set("选择要发送的文件...")
            file_path = filedialog.askopenfilename()
            if not file_path:
                self.status_var.set("文件选择已取消")
                self.file_sending = False
                return
                
            if not os.path.isfile(file_path):
                self.status_var.set("文件不存在或不是普通文件")
                self.file_sending = False
                return
                
            self.status_var.set(f"准备发送文件: {os.path.basename(file_path)}")
            
            # 先发送文件传输指令
            self.send_message_async('sendF')
            time.sleep(1)  # 等待对方准备
            
            # 现在发送文件
            self.status_var.set(f"正在发送文件: {os.path.basename(file_path)}")
            
            HOST = self.ip_address
            PORT = 5000
            file_size = os.path.getsize(file_path)
            file_basename = os.path.basename(file_path)
            filename_bytes = file_basename.encode() + b'\x00'  # NULL终止文件名

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(10.0)  # 设置超时
                try:
                    s.connect((HOST, PORT))
                except socket.timeout:
                    self.status_var.set("连接超时，文件传输失败")
                    self.file_sending = False
                    return
                
                # 发送文件大小（8字节）
                s.sendall(struct.pack('!Q', file_size))  # 使用8字节无符号整数
            
                # 发送文件名（含NULL终止符）
                s.sendall(filename_bytes)
            
                # 发送文件内容
                sent = 0
                try:
                    with open(file_path, 'rb') as f:
                        while sent < file_size and self.running:
                            data = f.read(4096)
                            if not data:
                                break
                            s.sendall(data)
                            sent += len(data)
                            self.status_var.set(f"发送进度: {sent}/{file_size} 字节 ({sent/file_size*100:.1f}%)")
                            self.root.update()
                except Exception as e:
                    self.status_var.set(f"文件发送错误: {str(e)}")
            
            if sent == file_size:
                self.status_var.set(f"文件发送完成 (共发送 {sent} 字节)")
                self.display_message(f"已发送文件: {file_basename}")
            else:
                self.status_var.set(f"文件发送中断 (已发送 {sent}/{file_size} 字节)")
        except Exception as e:
            self.status_var.set(f"文件发送错误: {str(e)}")
        finally:
            self.file_sending = False
    
    def send_message_async(self, message):
        # 在后台线程中发送消息
        def send():
            encrypted_message = self.cipher_suite.encrypt(message.encode('utf-8'))
            
            if self.mode == "TCP":
                try:
                    if self.tcp_client_socket:
                        self.tcp_client_socket.sendall(encrypted_message)
                except:
                    pass
            else:  # UDP
                try:
                    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    udp_addr = (self.ip_address, 9999)
                    udp_socket.sendto(encrypted_message, udp_addr)
                    udp_socket.close()
                except:
                    pass
        
        threading.Thread(target=send, daemon=True).start()
    
    def receive_file(self):
        if self.file_receiving:
            self.status_var.set("当前已有文件正在接收，请等待...")
            return
            
        self.file_receiving = True
        self.status_var.set("准备接收文件...")
        
        try:
            HOST = '0.0.0.0'
            PORT = 5000

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(10.0)  # 设置超时
                s.bind((HOST, PORT))
                s.listen()
                self.status_var.set(f"文件接收服务器已启动，正在 {HOST}:{PORT} 监听...")
                
                try:
                    conn, addr = s.accept()
                except socket.timeout:
                    self.status_var.set("文件接收超时")
                    self.file_receiving = False
                    return
                    
                with conn:
                    self.status_var.set(f"已连接客户端: {addr}")
                    conn.settimeout(10.0)  # 设置超时
        
                    # 接收文件大小（8字节）
                    file_size_bytes = conn.recv(8)
                    if len(file_size_bytes) != 8:
                        self.status_var.set("无效的文件大小头")
                        self.file_receiving = False
                        return
                        
                    file_size = struct.unpack('!Q', file_size_bytes)[0]  # 使用8字节无符号整数
            
                    # 接收文件名（NULL终止）
                    buffer = bytearray()
                    start_time = time.time()
                    while True:
                        if time.time() - start_time > 10:
                            self.status_var.set("文件名接收超时")
                            self.file_receiving = False
                            return
                            
                        chunk = conn.recv(1)
                        if not chunk:
                            self.status_var.set("连接中断")
                            self.file_receiving = False
                            return
                            
                        if chunk == b'\x00':
                            break
                            
                        buffer.extend(chunk)
                        if len(buffer) > 4096:
                            self.status_var.set("文件名过长")
                            self.file_receiving = False
                            return
                    
                    filename = buffer.decode()
                    self.status_var.set(f"正在接收文件: {filename} (大小: {file_size} 字节)")
            
                    # 接收文件内容
                    received = 0
                    try:
                        with open(filename, 'wb') as f:
                            start_time = time.time()
                            while received < file_size and self.running:
                                if time.time() - start_time > 30:  # 30秒超时
                                    self.status_var.set("文件接收超时")
                                    break
                                    
                                # 计算剩余字节数
                                remaining = file_size - received
                                chunk_size = 4096 if remaining > 4096 else remaining
                                
                                data = conn.recv(chunk_size)
                                if not data:
                                    self.status_var.set("连接提前关闭")
                                    break
                                    
                                f.write(data)
                                received += len(data)
                                self.status_var.set(f"接收进度: {received}/{file_size} 字节 ({received/file_size*100:.1f}%)")
                                self.root.update()
                    except Exception as e:
                        self.status_var.set(f"文件接收错误: {str(e)}")
            
                    if received == file_size:
                        self.status_var.set("文件接收完成")
                        self.display_message(f"已接收文件: {filename}")
                    else:
                        self.status_var.set(f"警告: 文件不完整 (已接收 {received}/{file_size} 字节)")
                        messagebox.showwarning("文件接收", f"文件不完整 (已接收 {received}/{file_size} 字节)")

        except Exception as e:
            self.status_var.set(f"文件接收错误: {str(e)}")
            messagebox.showerror("文件接收错误", str(e))
        finally:
            self.file_receiving = False
    
    def display_message(self, message):
        self.chat_history.config(state=tk.NORMAL)
        self.chat_history.insert(tk.END, message + "\n")
        self.chat_history.config(state=tk.DISABLED)
        self.chat_history.yview(tk.END)
        self.root.update()  # 强制更新UI
    
    def show_help(self):
        help_text = """=== 加密聊天应用使用指南 ===

1. 设置:
   - 生成或输入密钥: 双方必须使用相同的密钥
   - 输入对方IP地址
   - 选择通信模式(TCP或UDP)

2. 功能:
   - 发送消息: 在输入框中输入消息并点击发送或按Enter
   - 发送文件: 点击"发送文件"按钮选择并发送文件（输入sendF)
   - 查看历史记录: 查看加密存储的聊天历史

3. 注意事项:
   - 传文件时TCP模式更快
   - UDP模式可以支持多用户聊天
   - 聊天记录只能使用首次运行时生成的密钥访问
   - 文件传输过程中请勿重复操作

版本: 1.0.O GUI
作者：LEO
协议: Apache License Version 2.0
"""
        messagebox.showinfo("帮助", help_text)
    
    def on_close(self):
        self.running = False
        if self.tcp_client_socket:
            try:
                self.tcp_client_socket.close()
            except:
                pass
        self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    #print("DEBUG")
    #n = input(":")
    #if n == "VERSION" :
        #print("0.3.4")
    app = ChatApplication(root)
    root.mainloop()
