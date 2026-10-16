# Diagnostic only: the unmodified demo, with a pause before the SIEM sink's socket is closed (Nagle/RST theory)
import sys, time
import two_key.siem_sinks as K
od=K.SyslogSink.close
def close(self):
    time.sleep(float(__import__("os").environ.get("PAUSE","0.5"))); od(self)
K.SyslogSink.close=close
from two_key.cli import main
sys.argv=["two-key","demo","--siem",sys.argv[1]]
sys.exit(main())
