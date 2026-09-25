import pytest
import tempfile
import shutil
from pathlib import Path
from PIL import Image
import fitz

@pytest.fixture
def temp_dir():
    d = Path(tempfile.mkdtemp(prefix="filesanitizer_test_"))
    yield d
    shutil.rmtree(d, ignore_errors=True)

@pytest.fixture
def sample_image(temp_dir):
    img_path = temp_dir / "test_image.png"
    img = Image.new("RGBA", (100, 100), color=(255, 0, 0, 128))
    img.save(img_path, format="PNG")
    return img_path

@pytest.fixture
def sample_pdf(temp_dir):
    pdf_path = temp_dir / "test_document.pdf"
    doc = fitz.open()
    page = doc.new_page(width=300, height=300)
    page.insert_text((50, 50), "Hello FileSanitizer World! Visit https://example.com")
    doc.metadata = {
        "title": "Confidential Report",
        "author": "John Doe",
        "creator": "Word Processor",
        "producer": "FileSanitizer Generator"
    }
    doc.save(str(pdf_path))
    doc.close()
    return pdf_path
