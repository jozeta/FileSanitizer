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

@pytest.fixture(autouse=True)
def isolate_test_environment(monkeypatch, tmp_path):
    """
    Ensure no test execution can ever mutate or overwrite production settings
    or custom YARA rules on disk.
    """
    import copy
    import json
    from app.core.settings_store import settings_store, DEFAULT_SETTINGS
    from app.core.yara_manager import yara_manager, DEFAULT_RULES

    # 1. Isolate SettingsStore
    original_settings_data = copy.deepcopy(settings_store._data)
    original_get_config_dir = settings_store._get_config_dir

    test_config_dir = tmp_path / "test_config"
    test_config_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(settings_store, "_get_config_dir", lambda: test_config_dir)
    settings_store._data = copy.deepcopy(original_settings_data) if original_settings_data else json.loads(json.dumps(DEFAULT_SETTINGS))
    # Write isolated copy to test dir
    settings_store._save()

    # 2. Isolate YaraManager
    original_get_rules_dir = yara_manager._get_rules_dir

    test_yara_dir = tmp_path / "test_yara_rules"
    test_yara_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(yara_manager, "_get_rules_dir", lambda: test_yara_dir)
    yara_manager._init_storage()

    yield

    # Restore SettingsStore
    settings_store._data = original_settings_data
    monkeypatch.setattr(settings_store, "_get_config_dir", original_get_config_dir)

    # Restore YaraManager
    monkeypatch.setattr(yara_manager, "_get_rules_dir", original_get_rules_dir)



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
