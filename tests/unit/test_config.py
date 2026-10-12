from solomon.config import ConfigManager


def test_config_load_empty(fake_config_dir):
    manager = ConfigManager(config_dir=fake_config_dir)
    manager.load()
    assert manager.get("some.key") is None
    assert manager.get("some.key", "default") == "default"


def test_config_load_valid(fake_config_dir):
    fake_config_dir.mkdir(parents=True, exist_ok=True)
    config_file = fake_config_dir / "config.toml"
    config_file.write_text('title = "Solomon"\n[settings]\nenabled = true\n')

    manager = ConfigManager(config_dir=fake_config_dir)
    manager.load()

    assert manager.get("title") == "Solomon"
    assert manager.get("settings.enabled") is True
    assert manager.get("settings.missing", "fallback") == "fallback"
