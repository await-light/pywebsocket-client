import re
import ssl
import json
import socket
import struct

ws_opcode = {
    "text": 0x01,
    "binary": 0x02,
    "close": 0x08,
    "ping": 0x09,
    "pong": 0x0a
}

def isssl(url):
    # -1: neither
    # 0 : without ssl
    # 1 : ssl
    if url.startswith("ws://"):
        return 0
    elif url.startswith("wss://"):
        return 1
    else:
        return -1

def gethostname_by_wsurl(url):
    url = re.findall(r"^wss?://([^/]+)/.+$", url)
    if url:
        return url[0]
    else:
        return -1

def websocket_textframe(payload_data, maskingkey):
    mk = maskingkey
    paylen, bit, extendbits = len(payload_data), 0, ''
    if paylen < 0b1111110:
        bit = (1 << 7) + paylen
    elif 0b1111110 <= paylen <= 0xffff:
        bit = (1 << 7) + 0b1111110
        extendbits = 'L'
    elif paylen > 0xffff:
        bit = (1 << 7) + 0b1111111
        extendbits = 'Q'
    package = struct.pack("!BB%s4B%dB" % (extendbits, paylen),
                          (1 << 7) + ws_opcode["text"],
                          *(bit, paylen) if bit == (126 or 127) else (bit, ),
                          *mk,
                          *[ord(payload_data[i])^mk[i%4] for i in range(paylen)]
                          )
    return package

class WebsocketConnection:
    def __init__(self, url, port=443, debug=False):
        self._url = url
        self._port = port
        self._debug = debug
        self._wslocal = {
            "http_header": ("GET %s HTTP/1.1\r\n" \
                           "Host: hack.chat\r\n" \
                           "Connection: Upgrade\r\n" \
                           "Pragma: no-cache\r\n" \
                           "Cache-Control: no-cache\r\n" \
                           "User-Agent: hellojntm\r\n" \
                           "Upgrade: websocket\r\n" \
                           "Origin: https://hack.chat\r\n" \
                           "Sec-WebSocket-Version: 13\r\n" \
                           "Accept-Encoding: gzip, deflate, br\r\n" \
                           "Accept-Language: zh-CN,zh;q=0.9\r\n" \
                           "Sec-WebSocket-Key: 5mS/42vAskinpDkLDlZffQ==\r\n" \
                           "Sec-WebSocket-Extensions: permessage-deflate; " \
                           "client_max_window_bits\r\n\r\n" % (self._url)).encode(),
            "masking_key": (0x11, 0x45, 0x14, 0x19)
        }
        type_ = isssl(self._url)
        hostname = gethostname_by_wsurl(self._url)
        if type_ == -1 or hostname == -1:
            self.log("The url is not correct.")
            return
        sock = socket.create_connection((hostname, self._port))
        if type_ == 1:
            context = ssl.create_default_context()
            self.s = context.wrap_socket(sock, server_hostname=hostname)
        else:
            self.s = sock
        self.s.send(self._wslocal["http_header"])
        self.log(self.s.recv())
    
    @property
    def wslocal(self):
        return self._wslocal

    def log(self, info):
        if self._debug:
            print(info)

    def send(self, text, masking_key=None):
        if not masking_key:
            masking_key = self._wslocal["masking_key"]
        self.s.send(websocket_textframe(text, masking_key))

    def recv(self):
        return self.s.recv(1024)

    def close(self):
        self.s.close()
