#!/usr/bin/env python3
'''
Simple program to test wireguard.get_devices
'''

import json
from python_wireguard import wireguard

for max_size in range(-2,5):
    print(f"maxsize={max_size}")
    RESULT,rc=wireguard.get_devices(max_size)
    # pylint: disable=line-too-long
    print(f" maxsize {max_size} return: result='{RESULT}' length result={len(RESULT)}, return code={rc}")

MEM_CACHE_SIZE=4096

while True:
    print(f"MEM_CACHE_SIZE={MEM_CACHE_SIZE}")
    RESULT,ret=wireguard.get_devices(MEM_CACHE_SIZE)
    if ret >= 0:
        break
    MEM_CACHE_SIZE = int(MEM_CACHE_SIZE*1.1+1)
    # pylint: disable=line-too-long
    print(f"  MEM_CACHE_SIZE changed, new size is ={MEM_CACHE_SIZE}, result len={len(RESULT)}, return code was {ret}")

print(f"length = {len(RESULT)}")
print(RESULT)
print()
device_list=json.loads(RESULT)
RESULT=""
for dev in device_list:
    print(f">>>>>>>>>>>>>>>>{dev}")
    print(json.dumps(device_list[dev],indent=2))

#print(json.dumps(json.loads(RESULT),indent=2))
