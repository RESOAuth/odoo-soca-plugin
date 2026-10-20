"""Load the protocol package without importing an uninstalled host runtime."""
import sys
import types
from pathlib import Path

root = Path(__file__).resolve().parents[1] / "auth_soca"
package = types.ModuleType("soca_test_package")
package.__path__ = [str(root)]
sys.modules["soca_test_package"] = package
