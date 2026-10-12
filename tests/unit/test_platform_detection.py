from unittest import mock

from solomon.platform.base.capabilities import PrivilegeLevel
from solomon.platform.linux.ubuntu.detection import UbuntuDetector
from solomon.platform.windows.detection import WindowsDetector


@mock.patch("platform.release", return_value="10")
@mock.patch("platform.version", return_value="10.0.19041")
@mock.patch("ctypes.windll.shell32.IsUserAnAdmin", return_value=1)
@mock.patch(
    "shutil.which", side_effect=lambda cmd: "fake_path" if cmd in ["powershell", "cmd"] else None
)
def test_windows_detector_admin(mock_which, mock_is_admin, mock_version, mock_release):
    detector = WindowsDetector()
    capabilities = detector.detect()

    assert capabilities.platform == "Windows 10 (Build 10.0.19041)"
    assert capabilities.privilege_level == PrivilegeLevel.ADMINISTRATOR
    assert capabilities.has_capability("windows.powershell") is True
    assert capabilities.has_capability("cross.psutil") is True
    assert capabilities.has_capability("windows.wmic") is False


@mock.patch("platform.release", return_value="10")
@mock.patch("ctypes.windll.shell32.IsUserAnAdmin", return_value=0)
def test_windows_detector_standard_user(mock_is_admin, mock_release):
    detector = WindowsDetector()
    capabilities = detector.detect()
    assert capabilities.privilege_level == PrivilegeLevel.STANDARD_USER


@mock.patch("os.geteuid", return_value=0, create=True)
@mock.patch("solomon.platform.linux.ubuntu.detection.Path.exists", return_value=True)
@mock.patch(
    "builtins.open", new_callable=mock.mock_open, read_data='PRETTY_NAME="Ubuntu 22.04 LTS"'
)
@mock.patch(
    "shutil.which", side_effect=lambda cmd: "fake_path" if cmd in ["systemctl", "apt"] else None
)
def test_ubuntu_detector_root(mock_which, mock_open, mock_exists, mock_geteuid):
    detector = UbuntuDetector()
    capabilities = detector.detect()

    assert capabilities.platform == "Ubuntu 22.04 LTS"
    assert capabilities.privilege_level == PrivilegeLevel.ROOT
    assert capabilities.has_capability("linux.systemd") is True
    assert capabilities.has_capability("cross.psutil") is True
    assert capabilities.has_capability("linux.ufw") is False


@mock.patch("os.geteuid", return_value=1000, create=True)
@mock.patch("solomon.platform.linux.ubuntu.detection.Path.exists", return_value=False)
@mock.patch("platform.release", return_value="5.15.0")
def test_ubuntu_detector_non_root(mock_release, mock_exists, mock_geteuid):
    detector = UbuntuDetector()
    capabilities = detector.detect()

    assert capabilities.platform == "Linux 5.15.0"
    assert capabilities.privilege_level == PrivilegeLevel.NON_ROOT
