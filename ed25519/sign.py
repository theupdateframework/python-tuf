import sys
import binascii
import ed25519

# examples of inputs: see sign.input
# should produce no output: python sign.py < sign.input

# warning: currently 37 seconds/line on a fast machine

# fields on each input line: sk, pk, m, sm
# each field hex
# each field colon-terminated
# sk includes pk at end
# sm includes m at end

while 1:
  line = sys.stdin.readline()
  if not line: break
  x = line.split(':')
  sk = binascii.unhexlify(x[0][0:64])
  pk = ed25519.publickey(sk)
  m = binascii.unhexlify(x[2])
  s = ed25519.signature(m,sk,pk)
  ed25519.checkvalid(s,m,pk)
  forgedsuccess = 0
  try:
    if len(m) == 0:
      forgedm = "x"
    else:
      forgedmlen = len(m)
      forgedm = ''.join([chr(ord(m[i])+(i==forgedmlen-1)) for i in range(forgedmlen)])
    ed25519.checkvalid(s,forgedm,pk)
    forgedsuccess = 1
  except:
    pass
  assert not forgedsuccess
  assert x[0] == binascii.hexlify(sk + pk)
  assert x[1] == binascii.hexlify(pk)
  assert x[3] == binascii.hexlify(s + m)
