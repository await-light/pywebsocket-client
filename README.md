# pywebsocket-client
A simple python websocket client

## example
connect to `wss://hack.chat/chat-ws`
```python
import json
r = WebsocketConnection("wss://hack.chat/chat-ws")
r.send((json.dumps({"cmd": "join",
                   "nick": "awaot",
                   "channel": "your-channel"})))
r.sendorigin(websocket_pingframe())
while True:
    print(r.recv())
r.close()
```
