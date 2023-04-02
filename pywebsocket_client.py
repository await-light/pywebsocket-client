import re
import ssl
import random
import socket
import struct

WS_OPCODE = {
    "text": 0x01,
    "binary": 0x02,
    "close": 0x08,
    "ping": 0x09,
    "pong": 0x0a
}

def isssl(url):
    '''
    ssl is used or not
    RETURN:
        1: use ssl
        0: not use ssl or this is a misformatted url
    '''
    if url.startswith("wss://"):
        return 1
    else:
        return 0

def get_hostname_or_ipport_by_wsurl(url):
    '''
    return hostname or ip&port
    RETURN:
        (ip, port): ip and port
        (hostname, 443): hostname
        -1: misformatted url
    '''
    isipport = re.findall(r"^wss?://([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}"
                          r"\.[0-9]{1,3}):([0-9]{1,5})/.+$", url)
    ishostname = re.findall(r"^wss?://(.+)/.+$", url)
    if isipport:
        return isipport[0]
    elif ishostname:
        return (ishostname[0], 443)
    else:
        return -1

def websocket_textframe(payload_data, maskingkey=None):
    '''
    common websocket text frame
    RETURN:
        bytes data
    '''
    if not maskingkey:
        mk = tuple([random.randint(0, 0xff) for i in range(4)])
    else:
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
                          (1 << 7) + WS_OPCODE["text"],
                          *(bit, paylen) if bit == (126 or 127) else (bit, ),
                          *mk,
                          *[ord(payload_data[i])^mk[i%4] for i in range(paylen)]
                          )
    return package

def websocket_pingframe():
    '''
    websocket ping frame
    RETURN:
        bytes data
    '''
    package = struct.pack("!B",
                          (1 << 7) + WS_OPCODE["ping"])
    return package

class WebsocketConnection:
    MAX_RECV = 0xffff
    def __init__(self, url, debug=False):
        self._url = url
        self._debug = debug
        self._wslocal = {
            "http_header": ("GET %s HTTP/1.1\r\n" \
                           "Connection: Upgrade\r\n" \
                           "Host: NONE\r\n" \
                           "Origin: NONE\r\n" \
                           "User-Agent: Jntm\r\n" \
                           "Upgrade: websocket\r\n" \
                           "Sec-WebSocket-Version: 13\r\n" \
                           "Sec-WebSocket-Key: 5mS/42vAskinpDkLDlZffQ==\r\n\r\n" % (self._url)).encode()
        }
        # get hostname or ip&port
        hostname_or_ipport = get_hostname_or_ipport_by_wsurl(self._url)
        if hostname_or_ipport == -1:
            self.log("The url is not correct.")
            return
        else:
            self.log("Hostname: %s, Port: %s" % hostname_or_ipport)
            self._hostname, self._port = hostname_or_ipport
            self._port = int(self._port)
        # create socket connection
        sock = socket.create_connection((self._hostname, self._port))
        # use ssl or not
        type_ssl = isssl(self._url)
        if type_ssl == 1:
            context = ssl.create_default_context()
            self.s = context.wrap_socket(sock, server_hostname=self._hostname)
        else:
            self.s = sock
        self._http_shake_hand()
    
    @property
    def wslocal(self):
        return self._wslocal

    def _http_shake_hand(self):
        self.s.send(self._wslocal["http_header"])

    def log(self, info):
        if self._debug:
            print(info)

    def send(self, text):
        self.s.send(websocket_textframe(text))

    def sendorigin(self, data):
        '''
        send origin data
        '''
        self.s.send(data)

    def recv(self):
        data = self.s.recv(WebsocketConnection.MAX_RECV)
        if data:
            return data

    def close(self):
        self.s.close()
