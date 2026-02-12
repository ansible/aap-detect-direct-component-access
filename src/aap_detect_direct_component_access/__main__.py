"""Allow running as ``python -m aap_detect_direct_component_access``."""

from __future__ import print_function

import sys

from .detect import main

sys.exit(main())
