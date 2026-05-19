import pytest
from core.obfuscator import obfuscate, _hex_ip

def test_hex_ip():
    cmd = "curl 192.168.1.1"
    result = _hex_ip(cmd, "192.168.1.1")
    assert "0xC0A80101" in result

def test_windows_obfuscation():
    result = obfuscate(
        "certutil -urlcache http://192.168.1.1:8080/file",
        os_type="windows",
        binary="certutil",
        technique="env_var"
    )
    assert "SystemRoot" in result['obfuscated_command']

def test_linux_obfuscation():
    result = obfuscate(
        "curl http://192.168.1.1:8080/file",
        os_type="linux",
        binary="curl",
        technique="b64_bash"
    )
    assert "base64" in result['obfuscated_command']
