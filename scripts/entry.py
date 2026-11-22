from pathlib import Path
import sys

if "--version" in sys.argv:
    from rdp_guard import __version__
    print(f"RDP Guard {__version__}")
elif Path(sys.executable).stem.lower() == "guardservice":
    from rdp_guard.windows.service import GuardService, service_main
    service_main(GuardService)
elif Path(sys.executable).stem.lower() == "webservice":
    from rdp_guard.windows.service import WebService, service_main
    service_main(WebService)
else:
    from rdp_guard.cli import main
    raise SystemExit(main())
