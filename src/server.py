from common import *
import tkinter as tk
from tkinter import ttk
from tkinter import scrolledtext
from threading import *


# Author: 노재희
# Server Chat Program
# 객체 지향으로 작성
# Date  : 2018. 12. 19. -


Server_PrivateKey = './Server/Server_PrivateKey.txt'
Server_PublicKey = './Server/Server_PublicKey.txt'
Received_PublicKey = './Server/Received_PublicKey.txt'


class App():
    def __init__(self):
        self.BUFSIZ = 1024
        self.soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Tkinter GUI

        self.win = tk.Tk()
        self.win.title('PGP Server')
        self.win.resizable(False, False)

        ttk.Label(self.win, text='Host :').grid(row=1, column=0)
        ttk.Label(self.win, text='Port :').grid(row=2, column=0)

        ttk.Label(self.win, text='Server').grid(row=0, column=3)
        ttk.Separator(self.win, orient='vertical').grid(row=1, column=3, rowspan=6, sticky='ns')
        ttk.Separator(self.win, orient='horizontal').grid(row=0, column=0, columnspan=3, sticky='we')
        ttk.Separator(self.win, orient='horizontal').grid(row=0, column=4, columnspan=3, sticky='we')

        ttk.Label(self.win, text='© Jaehee').grid(column=3, row=7)
        ttk.Separator(self.win, orient='horizontal').grid(row=7, column=0, columnspan=3, sticky='we')
        ttk.Separator(self.win, orient='horizontal').grid(row=7, column=4, columnspan=3, sticky='we')

        self.chat_host = tk.StringVar()
        self.chat_host.set('localhost')
        chat_host_entered = ttk.Entry(self.win, width=30, textvariable=self.chat_host).grid(row=1, column=1)

        self.chat_port = tk.StringVar()
        chat_port_entered = ttk.Entry(self.win, width=30, textvariable=self.chat_port).grid(row=2, column=1)

        run_server = ttk.Button(self.win, text='서버 생성', command=lambda: Thread(target=self.create_chat).start())
        run_server.grid(row=1, column=2)

        ttk.Separator(self.win, orient='horizontal').grid(row=3, column=0, sticky='we')
        ttk.Label(self.win, text='Message').grid(column=1, row=3)
        ttk.Separator(self.win, orient='horizontal').grid(row=3, column=2, sticky='we')

        self.scr_message = scrolledtext.ScrolledText(self.win, width=62, height=24, wrap=tk.WORD)
        self.scr_message.grid(column=0, row=4, columnspan=3)

        ttk.Separator(self.win, orient='horizontal').grid(row=5, column=0, sticky='we')
        ttk.Label(self.win, text='Input').grid(column=1, row=5)
        ttk.Separator(self.win, orient='horizontal').grid(row=5, column=2, sticky='we')

        self.chat_message = tk.StringVar()
        chat_message_entered = ttk.Entry(self.win, width=30, textvariable=self.chat_message).grid(row=6, column=1)
        send_message = ttk.Button(self.win, text='전송', command=self.submit_chat).grid(row=6, column=2)

        ttk.Label(self.win, text='Log').grid(row=3, column=4)

        self.scr_log = scrolledtext.ScrolledText(self.win, width=62, height=24, wrap=tk.WORD)
        self.scr_log.grid(row=4, column=4)


    def create_chat(self):
        # TCP 연결 수립 및
        # 패킷 수신을 위한 Tread 생성

        HOST = self.chat_host.get()
        PORT = int(self.chat_port.get())
        ADDR = (HOST, PORT)

        self.scr_log.insert(tk.INSERT, '서버가 생성되었습니다.\n')
        self.scr_log.insert(tk.INSERT, '--------------------------------------------------------------\n')

        # RSA Key 생성
        Generate_Key(Server_PrivateKey, Server_PublicKey)

        # Server Public Key 전송
        for val in Send_Key(HOST, PORT + 1, Server_PublicKey):
            self.scr_log.insert(tk.INSERT, val + '\n')
            self.scr_log.insert(tk.INSERT, '--------------------------------------------------------------\n')

        # Client Public Key 받음
        for val in Receive_Key(HOST, PORT + 2, Received_PublicKey):
            self.scr_log.insert(tk.INSERT, val + '\n')
            self.scr_log.insert(tk.INSERT, '--------------------------------------------------------------\n')

        # TCP
        self.soc.bind(ADDR)
        self.soc.listen(5)
        self.soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.scr_log.insert(tk.INSERT, 'Server waiting for connection...\n')
        self.scr_log.insert(tk.INSERT, '--------------------------------------------------------------\n')
        self.server_socket, addr = self.soc.accept()
        self.scr_log.insert(tk.INSERT, 'Client connected from: ' + str(addr) + '\n')
        self.scr_log.insert(tk.INSERT, '--------------------------------------------------------------\n')

        while True:
            data = self.server_socket.recv(self.BUFSIZ)
            received = PGP_Decrypt(data, Server_PrivateKey, Received_PublicKey)
            self.scr_message.insert(tk.INSERT, 'Received: ' + str(received['message'].decode()) + '\n')

            for val in received['log']:
                self.scr_log.insert(tk.INSERT, str(val) + '\n')
                self.scr_log.insert(tk.INSERT, '--------------------------------------------------------------\n')


    def submit_chat(self):
        # 메시지 전송 메서드
        # 하이브리드 암호화 후 전송
        
        payload = PGP_Encrypt(self.chat_message.get().encode(), Server_PrivateKey, Received_PublicKey)
        self.scr_message.insert(tk.INSERT, '>>> ' + str(self.chat_message.get()) + '\n')

        for val in payload['log']:
            self.scr_log.insert(tk.INSERT, str(val) + '\n')
            self.scr_log.insert(tk.INSERT, '--------------------------------------------------------------\n')

        self.scr_log.insert(tk.INSERT, 'Encrypted: ' + str(base64.b64encode(payload['message'])) + '\n')
        self.scr_log.insert(tk.INSERT, '--------------------------------------------------------------\n')
        self.server_socket.send(payload['message'])

        # 입력창 내용 초기화
        self.chat_message.set('')


# GUI
app = App()  # Thread
app.win.mainloop()