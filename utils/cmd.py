#!/usr/bin/env python

import socket
import sys

sock_path = sys.argv[1]
command = " ".join(sys.argv[2:])

s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(sock_path)
s.send(command+"\r\n")
s.close()
