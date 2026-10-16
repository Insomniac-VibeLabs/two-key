# Diagnostic only: TCP_NODELAY on the sink's socket, no pause
import sys, socket
import two_key.siem_sinks as K
oo=K.SyslogSink._open_stream
def op(self):
    s=oo(self); s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1); return s
K.SyslogSink._open_stream=op
from two_key.cli import main
sys.argv=["two-key","demo","--siem",sys.argv[1]]
sys.exit(main())
