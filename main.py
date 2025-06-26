import sys
from cryptography.fernet import Fernet
import sqlite3
from threading import Thread
import time
from tqdm import *
# 生成密钥（需与客户端和服务器相同）
c = Fernet.generate_key()
# 打印出密钥并保存它
print(f"只用b‘’里的内容(Use only what is in b'')key: {c}")
key = input("key")  # 请确保使用相同的密钥
cipher_suite = Fernet(key)
ip = input("The IP address of the counterpart(对方的ip地址):")

# 创建数据库和表
def create_db():
    conn = sqlite3.connect('chat_records.db')
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS chat (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        message TEXT
                    )''')
    conn.commit()
    conn.close()
# 保存聊天记录
def save_chat(message):
    conn = sqlite3.connect('chat_records.db')
    cursor = conn.cursor()
    encrypted_message = cipher_suite.encrypt(message.encode('utf-8'))
    cursor.execute("INSERT INTO chat (message) VALUES (?)", (encrypted_message,))
    conn.commit()
    conn.close()



 
def select_file_or_folder():
    import tkinter as tk
    from tkinter import filedialog
    selected_path = None
 
    def select_folder():
        nonlocal selected_path
        folder_path = filedialog.askdirectory()
        if folder_path:
            selected_path = folder_path
            root.withdraw()
            root.destroy()
    
    def select_file():
        nonlocal selected_path
        file_path = filedialog.askopenfilename()
        if file_path:
            selected_path = file_path
            root.withdraw()
            root.destroy()
    
    def select_option():
        if option.get() == 1:
            select_file()
        elif option.get() == 2:
            select_folder()
 
    root = tk.Tk()
    root.withdraw()
 
    option = tk.IntVar()
 
    label = tk.Label(root, text="Select an option:")
    label.pack()
 
    file_button = tk.Radiobutton(root, text="选择一个文件", variable=option, value=1, command=select_file)
    file_button.pack()
 
    root.deiconify()  # 显示窗口
    root.mainloop()
 
    return selected_path
 


# 获取并解密聊天记录
def get_chat_records():
    conn = sqlite3.connect('chat_records.db')
    cursor = conn.cursor()
    cursor.execute("SELECT message FROM chat")
    records = cursor.fetchall()
    conn.close()

    for record in records:
        decrypted_message = cipher_suite.decrypt(record[0]).decode('utf-8')
        print(decrypted_message)
# 服务器端代码
def server():
    import socket
    print("Server is starting...")
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('0.0.0.0', 12345))
    server_socket.listen(1)
    while True:
        client_socket, addr = server_socket.accept()
        print(f"Connection from {addr}")
        while True:
            encrypted_message = client_socket.recv(1024)
            if encrypted_message:
                message = cipher_suite.decrypt(encrypted_message).decode('utf-8')
                print(f"From{addr}: {message}\n")
                save_chat(message)
                if message == 'sendF':
                    import socket
                    import struct
                    import os
                    from tqdm import tqdm  # 导入tqdm库

                    def read_until_null(sock, max_length=4096):
                        """读取数据直到遇到NULL终止符"""
                        buffer = bytearray()
                        while True:
                            chunk = sock.recv(1)
                            if not chunk:
                                raise ConnectionError("连接中断")
                            buffer.extend(chunk)
                            if chunk == b'\x00':
                                break
                            if len(buffer) > max_length:
                                raise ValueError("文件名过长")
                        return buffer[:-1]  # 排除NULL终止符

                    HOST = '0.0.0.0'
                    PORT = 5000

                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.bind((HOST, PORT))
                        s.listen()
                        print(f"服务器已启动，正在 {HOST}:{PORT} 监听...")
    
                        conn, addr = s.accept()
                        with conn:
                            print(f"已连接客户端: {addr}")
        
                            try:
                                # 接收文件大小（8字节）
                                file_size_bytes = conn.recv(8)
                                if len(file_size_bytes) != 8:
                                    raise ValueError("无效的文件大小头")
                                file_size = struct.unpack('!Q', file_size_bytes)[0]  # 使用8字节无符号整数
            
                                # 接收文件名（NULL终止）
                                filename_bytes = read_until_null(conn)
                                filename = filename_bytes.decode()
                                print(f"正在接收文件: {filename} (大小: {file_size} 字节)")
            
                                # 接收文件内容
                                received = 0
                                with open(filename, 'wb') as f, tqdm(
                                    total=file_size,  # 总大小
                                    unit='B',        # 单位
                                    unit_scale=True,  # 自动缩放单位
                                    desc=f"接收 {filename}",  # 进度条描述
                                    ncols=80          # 进度条宽度
                                ) as pbar:
                                    while received < file_size:
                                        data = conn.recv(min(4096, file_size - received))
                                        if not data:
                                            raise ConnectionError("连接提前关闭")
                                        f.write(data)
                                        received += len(data)
                                        pbar.update(len(data))
                                        if received == file_size:
                                            break# 更新进度条
            
                                if received == file_size:
                                    print("文件接收完成")
                                else:
                                    print(f"警告: 文件不完整 (已接收 {received}/{file_size} 字节)")

                            except Exception as e:
                                print(f"传输错误: {str(e)}")
                                # 删除不完整文件
                                if 'filename' in locals():
                                    if os.path.exists(filename):
                                        os.remove(filename)
        client_socket.close()
def sender():
    import socket
    import struct
    import os
    from tqdm import tqdm  # 导入tqdm库

    HOST = ip
    PORT = 5000

    #filename = input("请输入要发送的文件路径: ").strip()
    print("检查新出现的selection窗口，你可能需要重复选择一次文件它才会开始工作")
    select_file_or_folder()
    filename = select_file_or_folder()
    if not os.path.isfile(filename):
        print("文件不存在或不是普通文件")
        exit(1)

    file_size = os.path.getsize(filename)
    file_basename = os.path.basename(filename)
    filename_bytes = file_basename.encode() + b'\x00'  # NULL终止文件名

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        print(f"已连接到服务器 {HOST}:{PORT}")
    
        try:
            # 发送文件大小（8字节）
            s.sendall(struct.pack('!Q', file_size))  # 使用8字节无符号整数
        
            # 发送文件名（含NULL终止符）
            s.sendall(filename_bytes)
        
            # 发送文件内容
            sent = 0
            with open(filename, 'rb') as f, tqdm(
                total=file_size,  # 总大小
                unit='B',         # 单位
                unit_scale=True,  # 自动缩放单位
                desc=f"发送 {file_basename}",  # 进度条描述
                ncols=80         # 进度条宽度
            ) as pbar:
                while sent < file_size:
                    data = f.read(4096)
                    s.sendall(data)
                    sent += len(data)
                    pbar.update(len(data))  # 更新进度条
        
            print(f"文件发送完成 (共发送 {sent} 字节)")

        except Exception as e:
            print(f"传输错误: {str(e)}")
# 客户端代码
def client():
    import socket
    global ip
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    time.sleep(5)
    client_socket.connect((ip, 12345))
    
    while True:
        message = input('YOU(打sendF来输入文件）: ')
        encrypted_message = cipher_suite.encrypt(message.encode('utf-8'))
        client_socket.sendall(encrypted_message)

        if message.lower() == 'exit':
            break
        elif message == 'sendF':
            message == 'RECIVEPLZ'
            time.sleep(1)
            sender()
            
    client_socket.close()
def udpserver():
    from time import sleep
    import socket
    udp_addr = ('127.0.0.1', 9999)
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # 绑定端口
    udp_socket.bind(udp_addr)
 
    # 等待接收对方发送的数据
    while True:
        recv_data = udp_socket.recvfrom(1024)  # 1024表示本次接收的最大字节数
        # 打印接收到的数据
        print("[From %s:%d]:%s" % (recv_data[1][0], recv_data[1][1], recv_data[0].decode("utf-8")))
        if recv_data[0].decode("utf-8") == 'sendF':
            import socket
            import struct
            import os
            from tqdm import tqdm  # 导入tqdm库

            def read_until_null(sock, max_length=4096):
                """读取数据直到遇到NULL终止符"""
                buffer = bytearray()
                while True:
                    chunk = sock.recv(1)
                    if not chunk:
                        raise ConnectionError("连接中断")
                    buffer.extend(chunk)
                    if chunk == b'\x00':
                        break
                    if len(buffer) > max_length:
                        raise ValueError("文件名过长")
                return buffer[:-1]  # 排除NULL终止符

            HOST = '0.0.0.0'
            PORT = 5000

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind((HOST, PORT))
                s.listen()
                print(f"服务器已启动，正在 {HOST}:{PORT} 监听...")
    
                conn, addr = s.accept()
                with conn:
                    print(f"已连接客户端: {addr}")
        
                    try:
                        # 接收文件大小（8字节）
                        file_size_bytes = conn.recv(8)
                        if len(file_size_bytes) != 8:
                            raise ValueError("无效的文件大小头")
                        file_size = struct.unpack('!Q', file_size_bytes)[0]  # 使用8字节无符号整数
            
                        # 接收文件名（NULL终止）
                        filename_bytes = read_until_null(conn)
                        filename = filename_bytes.decode()
                        print(f"正在接收文件: {filename} (大小: {file_size} 字节)")
            
                        # 接收文件内容
                        received = 0
                        with open(filename, 'wb') as f, tqdm(
                            total=file_size,  # 总大小
                            unit='B',        # 单位
                            unit_scale=True,  # 自动缩放单位
                            desc=f"接收 {filename}",  # 进度条描述
                            ncols=80          # 进度条宽度
                        ) as pbar:
                            while received < file_size:
                                data = conn.recv(min(4096, file_size - received))
                                if not data:
                                    raise ConnectionError("连接提前关闭")
                                f.write(data)
                                received += len(data)
                                pbar.update(len(data))
                                if received == file_size:
                                    break# 更新进度条
            
                        if received == file_size:
                            print("文件接收完成")
                        else:
                            from tkinter import messagebox
                            import tkinter as tk
                            root = tk.Tk()
                            root.iconify()
                            tk.messagebox.showerror(title='警告', message='''文件不完整''')
                            root.withdraw()
                            print(f"警告: 文件不完整 (已接收 {received}/{file_size} 字节)")

                    except Exception as e:
                        from tkinter import messagebox
                        import tkinter as tk
                        root = tk.Tk()
                        root.iconify()
                        tk.messagebox.showerror(title='警告', message='''传输错误''')
                        root.withdraw()
                        print(f"传输错误: {str(e)}")
                        # 删除不完整文件
                        if 'filename' in locals():
                            if os.path.exists(filename):
                                os.remove(filename)
            
def udpclient():
    from time import sleep
    import socket
    # udp 通信地址，IP+端口号
    udp_addr = (ip, 9999)
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # 发送数据到指定的ip和端口,每隔1s发送一次，发送10次
    while True :
        word = input("YOU(sendF去发送文件）:")
        for i in range(1):
            if word == 'sendF':
                udp_socket.sendto((word) .encode('utf-8'), udp_addr)
                time.sleep(3)
                sender()
                
            udp_socket.sendto((word) .encode('utf-8'), udp_addr)
            print("send %d message")
            sleep(1)
    # 5. 关闭套接字
    udp_socket.close()

# 主程序入口
if __name__ == '__main__':
    # 创建数据库
    create_db()
    print("===Command List===")
    print("TCP --- USE TCP MODE TO START")
    print("UDP --- USE UDP MODE TO START")
    print("RECORD --- CHAT HISTORY")
    print("HELP --- HOW TO USE?(ILLUSTRATE)")
    print("VERSION")
    role = input(":")
    if role == 'RECORD':
        get_chat_records()
        time.sleep(30)
    elif role == 'UDP':
        thread3 = Thread(target=udpserver, args=())
        thread4 = Thread(target=udpclient, args=())
        thread3.start()  # 线程1开始
        thread4.start()
    elif role == 'TCP':
        thread1 = Thread(target=server, args=())
        thread2 = Thread(target=client, args=())
        thread1.start()  # 线程1开始
        thread2.start()
        time.sleep(30)
    elif role == 'HELP':
        print("CHI OR ENG")
        role2 = input(":")
        if role == 'CHI':
            print('''传文件TCP更快，UDP可以多个人同时聊天(你的聊天记录只能被第一次运行产生的密钥访问)''')
        elif role2 == 'ENG':
            print(''' TCP is faster to transfer files, UDP can chat with multiple people at the same time (your chat history can only be accessed by the key generated by the first run)''')
    elif role == 'VERSION':
        from tkinter import messagebox
        import tkinter as tk
        root = tk.Tk()
        root.iconify()
        tk.messagebox.showinfo(title='info', message='''Apache License Version 2.0 Application Version 0.3.3''')
        root.withdraw()
    #elif role == "GUI" :
        
    else:
       time.sleep(5)
