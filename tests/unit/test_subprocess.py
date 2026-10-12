import subprocess
from unittest.mock import MagicMock, patch

from solomon.platform.base.subprocess import SafeSubprocess


def test_safe_subprocess_success():
    proc = SafeSubprocess()

    with patch("subprocess.run") as mock_run:
        mock_result = MagicMock()
        mock_result.stdout = "hello\n"
        mock_result.stderr = ""
        mock_result.returncode = 0
        mock_run.return_value = mock_result

        res = proc.run(["echo", "hello"])
        assert res.success is True
        assert res.stdout == "hello"


def test_safe_subprocess_timeout():
    proc = SafeSubprocess(timeout=1)

    with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="sleep 10", timeout=1)):
        res = proc.run(["sleep", "10"])
        assert res.success is False
        assert "timed out" in res.error_message


def test_safe_subprocess_file_not_found():
    proc = SafeSubprocess()

    with patch(
        "subprocess.run", side_effect=FileNotFoundError("No such file or directory: 'fake_cmd'")
    ):
        res = proc.run(["fake_cmd"])
        assert res.success is False
        assert "Executable not found" in res.error_message
