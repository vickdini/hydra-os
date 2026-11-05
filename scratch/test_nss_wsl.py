import ctypes
import os

so_path = os.path.expanduser('~/bravetmp/opt/brave.com/brave/libnss3.so')
print('Loading', so_path)
nss = ctypes.CDLL(so_path)
res = nss.NSS_NoDB_Init(None)
print('Result with bundled libnss3 and system softokn/freebl:', res)
