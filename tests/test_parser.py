import pytest
from net_audit.parser import parse_interfaces, parse_version, parse_config


class TestParseInterfaces:
    def test_basic_table(self):
        raw = ("Interface              IP-Address      OK? Method Status                Protocol\n"
               "GigabitEthernet0/0     10.0.0.1        YES NVRAM  up                    up\n"
               "GigabitEthernet0/1     unassigned      YES NVRAM  administratively down down")
        result = parse_interfaces(raw)
        assert len(result) == 2
        assert result[0]["interface"] == "GigabitEthernet0/0"
        assert result[0]["status"] == "up"

    def test_empty_input(self):
        assert parse_interfaces("") == []


class TestParseVersion:
    def test_parses_version(self):
        raw = ("Cisco IOS Software, C3750 Software (C3750-IPSERVICESK9-M), "
               "Version 15.2(4)E10, RELEASE SOFTWARE\n\n"
               "router uptime is 5 days, 3 hours, 22 minutes")
        result = parse_version(raw)
        assert "15.2" in result.get("version", "")
        assert "5 days" in result.get("uptime", "")

    def test_unknown(self):
        assert parse_version("") == {}


class TestParseConfig:
    def test_splits_lines(self):
        raw = "hostname rtr01\ninterface GigabitEthernet0/0\n ip address 10.0.0.1 255.255.255.0"
        result = parse_config(raw)
        assert "hostname rtr01" in result
        assert len(result) == 3

    def test_empty(self):
        assert parse_config("") == []
