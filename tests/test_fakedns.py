"""Tests for FakeDNS detection and filtering."""

from xray_analyzer.diagnostics.dns_checker import FAKEDNS_NETWORKS, is_fakedns_ip


class TestIsFakednsIp:
    def test_ipv4_in_pool(self):
        assert is_fakedns_ip("198.18.0.1") is True
        assert is_fakedns_ip("198.18.0.69") is True
        assert is_fakedns_ip("198.19.255.255") is True

    def test_ipv4_outside_pool(self):
        assert is_fakedns_ip("1.1.1.1") is False
        assert is_fakedns_ip("198.17.255.255") is False
        assert is_fakedns_ip("198.20.0.0") is False
        assert is_fakedns_ip("8.8.8.8") is False

    def test_ipv6_in_pool(self):
        assert is_fakedns_ip("fc00::1") is True
        assert is_fakedns_ip("fc00::ffff") is True

    def test_ipv6_outside_pool(self):
        assert is_fakedns_ip("2001:db8::1") is False
        assert is_fakedns_ip("::1") is False

    def test_invalid_input(self):
        assert is_fakedns_ip("not-an-ip") is False
        assert is_fakedns_ip("") is False

    def test_networks_are_expected_pools(self):
        """Ensure the pool constants haven't drifted from Xray defaults."""
        assert len(FAKEDNS_NETWORKS) == 2
        assert str(FAKEDNS_NETWORKS[0]) == "198.18.0.0/15"
        assert str(FAKEDNS_NETWORKS[1]) == "fc00::/18"


class TestFallbackIpFiltering:
    """Test that FakeDNS IPs are filtered when selecting fallback IPs."""

    def test_real_ips_pass_through(self):
        local_ips = ["185.191.118.179", "104.16.0.1"]
        real_ips = [ip for ip in local_ips if not is_fakedns_ip(ip)]
        assert real_ips == ["185.191.118.179", "104.16.0.1"]

    def test_fakedns_ips_filtered(self):
        local_ips = ["198.18.0.69"]
        real_ips = [ip for ip in local_ips if not is_fakedns_ip(ip)]
        assert real_ips == []

    def test_mixed_ips_keep_real(self):
        local_ips = ["198.18.0.69", "185.191.118.179"]
        real_ips = [ip for ip in local_ips if not is_fakedns_ip(ip)]
        assert real_ips == ["185.191.118.179"]

    def test_empty_list(self):
        local_ips: list[str] = []
        real_ips = [ip for ip in local_ips if not is_fakedns_ip(ip)]
        assert real_ips == []
