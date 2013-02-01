import subprocess
import random
import time

PORT = random.randint(30000, 40000)

server_proc = subprocess.Popen(['python', 'simple_server.py', str(PORT)])

print "start server..."
time.sleep(20)

if server_proc.returncode is None:
  print '\n server is still running... killing it...'
  server_proc.kill()
print "\nend server."
