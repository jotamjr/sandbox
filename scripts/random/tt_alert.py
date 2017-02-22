#!/usr/bin/python

import time
import blinkt
import subprocess
import imaplib

def hide_all():
  for i in range (0, 8):
    blinkt.set_pixel(i, 0, 0, 0, 0)
    blinkt.show()

def lit_all():
  for i in range (0, 8):
    blinkt.set_pixel(i, 255, 0, 0, 0.5)
    blinkt.show()

def alert_tt():
  subprocess.Popen(['mplayer', '/home/pi/dev/LaunchWarning.ogg'])
  time.sleep(0.7)
  for i in range (0, 9):
    lit_all()
    time.sleep(0.1)
    hide_all()
    time.sleep(0.080)

username = ''
password = ''
server = ''

imap = imaplib.IMAP4_SSL(server)
imap.login(username, password)

status, messages = imap.select('INBOX')

if status != 'OK':
  print "Incorrect mail box"
  exit()

if messages[0] != '0':
  #print "[D] Alert new TT"
  alert_tt()
else:
  print "[D] No new threats
