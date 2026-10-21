#!/bin/sh
# PAM behaviour regression test. Run as root on a hardened minion AFTER the highstate.
# Creates two throwaway users, checks that WRONG passwords are refused on every service
# that uses common-auth, that a correct one works, and that the pam_wheel restriction on
# `su` / `su -` (service su-l) holds. Cleans up after itself. Exit code = number of FAILs.
# (A scan can be green while a stack is open: this checks real behaviour, not file text.)
set -u
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 2; }
command -v python3 >/dev/null || { echo "python3 required" >&2; exit 2; }
T=$(mktemp -d); chmod 755 "$T"
A=s2sreg_a$$; B=s2sreg_b$$; PW=$(head -c 18 /dev/urandom | base64 | tr -d '=+/'); FAIL=0
cleanup() { pkill -u "$A" 2>/dev/null; pkill -u "$B" 2>/dev/null; sleep 1
  userdel -rf "$A" >/dev/null 2>&1; userdel -rf "$B" >/dev/null 2>&1; rm -rf "$T"; }
trap cleanup EXIT INT TERM
ok()   { echo "PASS  $1"; }
bad()  { echo "FAIL  $1"; FAIL=$((FAIL+1)); }
skip() { echo "SKIP  $1"; }

cat > "$T/pamt.py" <<'EOF'
import ctypes, ctypes.util, sys
pam=ctypes.CDLL(ctypes.util.find_library("pam")); libc=ctypes.CDLL(ctypes.util.find_library("c"))
class M(ctypes.Structure): _fields_=[("msg_style",ctypes.c_int),("msg",ctypes.c_char_p)]
class R(ctypes.Structure): _fields_=[("resp",ctypes.c_char_p),("resp_retcode",ctypes.c_int)]
CONV=ctypes.CFUNCTYPE(ctypes.c_int,ctypes.c_int,ctypes.POINTER(ctypes.POINTER(M)),ctypes.POINTER(ctypes.POINTER(R)),ctypes.c_void_p)
class C(ctypes.Structure): _fields_=[("conv",CONV),("data",ctypes.c_void_p)]
user,pw,svc=sys.argv[1],sys.argv[2].encode(),sys.argv[3].encode()
libc.calloc.restype=ctypes.c_void_p; libc.strdup.restype=ctypes.c_void_p
def cb(n,msg,resp,_):
    arr=libc.calloc(n,ctypes.sizeof(R)); resp[0]=ctypes.cast(arr,ctypes.POINTER(R))
    for i in range(n):
        if msg[i].contents.msg_style in (1,2):
            ctypes.memmove(arr+i*ctypes.sizeof(R),ctypes.byref(ctypes.c_void_p(libc.strdup(pw))),8)
    return 0
c=C(CONV(cb),None); h=ctypes.c_void_p()
assert pam.pam_start(svc,user.encode(),ctypes.byref(c),ctypes.byref(h))==0
r=pam.pam_authenticate(h,0); pam.pam_end(h,0); sys.exit(1 if r else 0)
EOF
cat > "$T/su.py" <<'EOF'
import pty,os,sys,time,select
user,pw,login=sys.argv[1],sys.argv[2],sys.argv[3]=="login"
pid,fd=pty.fork()
if pid==0:
    os.execvp("su",["su"]+(["-"] if login else [])+[user,"-c","echo SU_OK"])
buf=b""; sent=False; end=time.time()+15
while time.time()<end:
    r,_,_=select.select([fd],[],[],1)
    if r:
        try: d=os.read(fd,4096)
        except OSError: break
        if not d: break
        buf+=d
        if b"assword" in buf and not sent: os.write(fd,(pw+"\n").encode()); sent=True
sys.exit(0 if b"SU_OK" in buf else 1)
EOF
chmod 644 "$T"/*.py

useradd -m "$A" && useradd -m "$B" && echo "$B:$PW" | chpasswd || { echo "cannot create test users" >&2; exit 2; }
pamok()  { python3 "$T/pamt.py" "$B" "$1" "$2" >/dev/null 2>&1; }

echo "== authentication through common-auth (wrong password must be refused)"
for svc in login sshd sudo passwd; do
  if [ -e /etc/pam.d/$svc ] || [ -e /usr/lib/pam.d/$svc ]; then
    if pamok "bad-$PW" $svc; then bad "$svc ACCEPTED a wrong password"; else ok "$svc refuses a wrong password"; fi
  else skip "$svc: no PAM service file"; fi
done
if pamok "$PW" sshd; then ok "sshd accepts the correct password"; else bad "sshd refused the correct password"; fi

echo "== su / su - restriction (pam_wheel group)"
G=$(grep -hE '^[[:space:]]*auth[[:space:]]+required[[:space:]]+pam_wheel\.so' /etc/pam.d/su 2>/dev/null | sed -n 's/.*group=\([^ ]*\).*/\1/p' | head -1)
if [ -z "$G" ] || ! getent group "$G" >/dev/null; then
  skip "su restriction not configured (no pam_wheel group=...)"
else
  for mode in su login; do
    n="su"; [ $mode = login ] && n="su -"
    gpasswd -d "$A" "$G" >/dev/null 2>&1
    if runuser -u "$A" -- python3 "$T/su.py" "$B" "$PW" $mode; then bad "$n: user OUTSIDE $G could switch user"; else ok "$n: user outside $G is refused"; fi
    usermod -aG "$G" "$A"
    if runuser -u "$A" -- python3 "$T/su.py" "$B" "$PW" $mode; then ok "$n: member of $G can switch user"; else bad "$n: member of $G was refused (su stack broken?)"; fi
    if runuser -u "$A" -- python3 "$T/su.py" "$B" "bad-$PW" $mode; then bad "$n: wrong password ACCEPTED"; else ok "$n: wrong password refused"; fi
  done
fi
echo; [ "$FAIL" = 0 ] && echo "RESULT: all checks passed" || echo "RESULT: $FAIL check(s) FAILED"
exit "$FAIL"
