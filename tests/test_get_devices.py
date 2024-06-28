#!/usr/bin/env python3

from python_wireguard import wireguard
import json

for max_size in range(-2,5):
    print(f"maxsize={max_size}")
    res,rc=wireguard.get_devices(max_size)
    print(f" maxsize {max_size} return: result='{res}' length result={len(res)}, return code={rc}")

mem_cache_size=4096

while True:
    print(f"mem_cache_size={mem_cache_size}")
    res,ret=wireguard.get_devices(mem_cache_size)
    if ret >= 0:
        break
    mem_cache_size = int(mem_cache_size*1.1+1)
    print(f"  mem_cache_size changed, new size is ={mem_cache_size}, res len={len(res)}, return code was {ret}")

print(f"length = {len(res)}")
print(res)
print()
device_list=json.loads(res)
res=""
for dev in device_list:
    print(f">>>>>>>>>>>>>>>>{dev}")
    print(json.dumps(device_list[dev],indent=2))

#print(json.dumps(json.loads(res),indent=2))
