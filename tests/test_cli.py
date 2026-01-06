"""
Macaron CLI Tests
Tests all CLI commands and options
"""

import subprocess
import sys
import json
import tempfile
import shutil
from pathlib import Path

# Path to macaron script
MACARON = Path(__file__).parent.parent / "macaron"


def run_macaron(*args):
    """Run macaron with arguments and return (returncode, stdout, stderr)"""
    result = subprocess.run(
        [sys.executable, str(MACARON)] + list(args),
        capture_output=True,
        text=True,
        timeout=30
    )
    return result.returncode, result.stdout, result.stderr


def get_output(*args):
    """Get combined stdout+stderr from macaron"""
    code, stdout, stderr = run_macaron(*args)
    return code, stdout + stderr


class TestVersion:
    """Test version and help commands"""
    
    def test_version(self):
        code, output = get_output("--version")
        assert code == 0
        assert "macaron" in output.lower()
        assert "2." in output  # Version 2.x
    
    def test_help(self):
        code, output = get_output("--help")
        assert code == 0
        assert "-s" in output
        assert "--scan" in output
        assert "-S" in output
        assert "-R" in output
        assert "-L" in output
        assert "-U" in output
        assert "-G" in output
        assert "-C" in output
        assert "-P" in output


class TestConfig:
    """Test configuration commands"""
    
    def test_config_show(self):
        code, output = get_output("-C")
        assert code == 0
        assert "config" in output.lower() or "Configuration" in output
    
    def test_pipeline_path(self):
        code, output = get_output("-P")
        assert code == 0
        assert "pipeline" in output.lower()


class TestStatus:
    """Test status command"""
    
    def test_status_empty(self):
        code, output = get_output("-S")
        assert code == 0
        # Should show banner or "no data" message


class TestUpdate:
    """Test update command"""
    
    def test_update_check(self):
        code, output = get_output("-U")
        assert code == 0
        assert "version" in output.lower() or "update" in output.lower()


class TestInputValidation:
    """Test input validation"""
    
    def test_invalid_target(self):
        code, output = get_output("-s", "invalid target!!!")
        # Should fail or skip invalid targets
        assert "invalid" in output.lower() or "skip" in output.lower() or code != 0
    
    def test_invalid_rate(self):
        code, output = get_output("-s", "example.com", "--rate", "-5")
        assert code == 1
        assert "rate" in output.lower() or "must be" in output.lower()
    
    def test_invalid_threads(self):
        code, output = get_output("-s", "example.com", "--threads", "0")
        assert code == 1
        assert "thread" in output.lower() or "must be" in output.lower()
    
    def test_missing_file(self):
        code, output = get_output("-F", "/nonexistent/file.txt")
        assert code == 1
        assert "not found" in output.lower() or "error" in output.lower()


class TestGallery:
    """Test gallery command"""
    
    def test_gallery_no_domain(self):
        code, output = get_output("-G")
        assert code == 1
        assert "domain" in output.lower() or "-d" in output.lower() or "specify" in output.lower()
    
    def test_gallery_missing_domain(self):
        code, output = get_output("-G", "-d", "nonexistent.domain.xyz")
        assert code == 1
        assert "not found" in output.lower() or "no data" in output.lower()


class TestExport:
    """Test export command"""
    
    def test_export_creates_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output_file = Path(tmpdir) / "export.json"
            code, output = get_output("-E", "-o", str(output_file))
            assert code == 0
            assert output_file.exists()
            
            # Verify JSON structure
            with open(output_file) as f:
                data = json.load(f)
            assert "exported_at" in data
            assert "targets" in data


class TestTools:
    """Test tools list command"""
    
    def test_list_tools(self):
        code, output = get_output("-L")
        assert code == 0
        assert "tool" in output.lower() or "installed" in output.lower()
        # Should list common tools
        assert "subfinder" in output.lower() or "Subdomain" in output


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v"])
