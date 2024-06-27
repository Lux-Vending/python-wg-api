#!/usr/bin/env python3

from python_wireguard import wireguard
import json

#res=wireguard.get_devices(1)
res=wireguard.key_pubkey("cGW1b7mOpPlmXH29zKKHFOwXCX5MVZLAQQOIUF2RvVQ=")
print(f"{type(res)}")
print(f"length = {len(res)}")
print(res)
if res == "broKgwldJkqCkv8cSWCAzmlf15la7e4x7ze61QaY8jY=":
    print ("good")
else:
    print ("ERROR!")
