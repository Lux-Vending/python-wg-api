#!/usr/bin/env python3

from python_wireguard import wireguard
import json

#res=wireguard.get_devices(1)
mem_cache_size=1411
#mem_cache_size=1552 # works
#mem_cache_size=1553 # malloc(): corrupted top size
#mem_cache_size=1585 # malloc(): corrupted top size
#mem_cache_size=1586 # works

while True:
    print(f"mem_cache_size={mem_cache_size}")
    res=wireguard.get_devices(mem_cache_size)
    if len(res) < mem_cache_size-10:
        break
    mem_cache_size = int(mem_cache_size*1.1+1)
    print(f"  mem_cache_size changed, new size is ={mem_cache_size}, res len={len(res)}")

#print(f"{type(res)}")
print(f"length = {len(res)}")
print(res)
print()
device_list=json.loads(res)
res=""
for dev in device_list:
    print(f">>>>>>>>>>>>>>>>{dev}")
    print(json.dumps(device_list[dev],indent=2))

#print(json.dumps(json.loads(res),indent=2))
