"""
Screenshot Gallery Tests
Tests for HTML gallery generation
"""

import tempfile
import shutil
from pathlib import Path
import sys

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent.parent))


class TestScreenshotGallery:
    """Test gallery generation"""
    
    def test_gallery_generation(self):
        """Test that gallery HTML is generated from screenshots"""
        # Import after path setup
        exec(open(Path(__file__).parent.parent / "macaron").read().split("if __name__")[0])
        
        with tempfile.TemporaryDirectory() as tmpdir:
            ss_dir = Path(tmpdir) / "gowitness"
            ss_dir.mkdir()
            
            # Create dummy screenshot files
            (ss_dir / "https-example-com.png").write_bytes(b"fake png data")
            (ss_dir / "https-api-example-com-8080.png").write_bytes(b"fake png data")
            
            # Generate gallery
            gallery_path = ScreenshotGallery.generate(ss_dir, "example.com")
            
            assert gallery_path is not None
            assert gallery_path.exists()
            assert gallery_path.name == "gallery.html"
            
            # Check HTML content
            html = gallery_path.read_text()
            assert "example.com" in html
            assert "Screenshot Gallery" in html
            assert "gallery" in html.lower()
    
    def test_gallery_empty_dir(self):
        """Test gallery returns None for empty directory"""
        exec(open(Path(__file__).parent.parent / "macaron").read().split("if __name__")[0])
        
        with tempfile.TemporaryDirectory() as tmpdir:
            ss_dir = Path(tmpdir) / "empty"
            ss_dir.mkdir()
            
            result = ScreenshotGallery.generate(ss_dir, "test.com")
            assert result is None
    
    def test_gallery_nonexistent_dir(self):
        """Test gallery returns None for nonexistent directory"""
        exec(open(Path(__file__).parent.parent / "macaron").read().split("if __name__")[0])
        
        result = ScreenshotGallery.generate(Path("/nonexistent/path"), "test.com")
        assert result is None
    
    def test_filename_to_url(self):
        """Test filename parsing"""
        exec(open(Path(__file__).parent.parent / "macaron").read().split("if __name__")[0])
        
        # Test various filename formats
        assert ScreenshotGallery._filename_to_url("https-example-com") == "https://example.com"
        assert ScreenshotGallery._filename_to_url("http-test-org-8080") == "http://test.org:8080"
        assert ScreenshotGallery._filename_to_url("https-api-example-com-443") == "https://api.example.com"
        assert ScreenshotGallery._filename_to_url("invalid") is None


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v"])
