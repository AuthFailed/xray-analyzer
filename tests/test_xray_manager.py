"""Tests for Xray config generation."""

from unittest.mock import patch

import pytest

from xray_analyzer.diagnostics.subscription_parser import ProxyShareURL
from xray_analyzer.diagnostics.xray_manager import _generate_xray_config


def _make_share(**kwargs) -> ProxyShareURL:
    """Helper to build a ProxyShareURL with defaults."""
    defaults = {
        "protocol": "vless",
        "name": "test",
        "server": "example.com",
        "port": 443,
        "raw_url": "vless://test",
        "uuid": "test-uuid",
        "network": "tcp",
        "security": "none",
    }
    defaults.update(kwargs)
    return ProxyShareURL(**defaults)


class TestVlessConfig:
    def test_basic_tcp(self):
        share = _make_share()
        cfg = _generate_xray_config(share, 10800, "user", "pass")

        assert cfg["outbounds"][0]["protocol"] == "vless"
        vnext = cfg["outbounds"][0]["settings"]["vnext"][0]
        assert vnext["address"] == "example.com"
        assert vnext["port"] == 443
        assert vnext["users"][0]["id"] == "test-uuid"

    def test_tls_settings(self):
        share = _make_share(security="tls", sni="cdn.example.com", fp="chrome")
        cfg = _generate_xray_config(share, 10800, "user", "pass")

        stream = cfg["outbounds"][0]["streamSettings"]
        assert stream["security"] == "tls"
        assert stream["tlsSettings"]["serverName"] == "cdn.example.com"
        assert stream["tlsSettings"]["fingerprint"] == "chrome"

    def test_reality_settings(self):
        share = _make_share(
            security="reality",
            sni="real.example.com",
            fp="chrome",
            pbk="testpubkey",
            sid="ab",
            spx="/",
        )
        cfg = _generate_xray_config(share, 10800, "user", "pass")

        stream = cfg["outbounds"][0]["streamSettings"]
        assert stream["security"] == "reality"
        rs = stream["realitySettings"]
        assert rs["publicKey"] == "testpubkey"
        assert rs["shortId"] == "ab"
        assert rs["serverName"] == "real.example.com"
        assert rs["fingerprint"] == "chrome"

    def test_reality_no_duplicate_server_name(self):
        """REALITY serverName should be set exactly once (no overwrite)."""
        share = _make_share(
            security="reality",
            sni="target.com",
            host="fallback.com",
            pbk="key",
            sid="00",
        )
        cfg = _generate_xray_config(share, 10800, "user", "pass")
        rs = cfg["outbounds"][0]["streamSettings"]["realitySettings"]
        assert rs["serverName"] == "target.com"

    def test_ws_transport(self):
        share = _make_share(network="ws", path="/ws", host="ws.example.com", security="tls", sni="ws.example.com")
        cfg = _generate_xray_config(share, 10800, "user", "pass")

        stream = cfg["outbounds"][0]["streamSettings"]
        assert stream["network"] == "ws"
        assert stream["wsSettings"]["path"] == "/ws"
        assert stream["wsSettings"]["headers"]["Host"] == "ws.example.com"

    def test_grpc_transport(self):
        share = _make_share(network="grpc", service_name="mygrpc", security="tls", sni="grpc.example.com")
        cfg = _generate_xray_config(share, 10800, "user", "pass")

        stream = cfg["outbounds"][0]["streamSettings"]
        assert stream["grpcSettings"]["serviceName"] == "mygrpc"

    def test_httpupgrade_transport(self):
        share = _make_share(network="httpupgrade", path="/hu", host="hu.example.com")
        cfg = _generate_xray_config(share, 10800, "user", "pass")

        stream = cfg["outbounds"][0]["streamSettings"]
        assert stream["httpupgradeSettings"]["path"] == "/hu"
        assert stream["httpupgradeSettings"]["host"] == "hu.example.com"

    def test_splithttp_transport(self):
        share = _make_share(network="splithttp", path="/sh", host="sh.example.com")
        cfg = _generate_xray_config(share, 10800, "user", "pass")

        stream = cfg["outbounds"][0]["streamSettings"]
        assert stream["splithttpSettings"]["path"] == "/sh"
        assert stream["splithttpSettings"]["host"] == "sh.example.com"

    def test_http_transport(self):
        share = _make_share(network="http", path="/h2", host="h2.example.com")
        cfg = _generate_xray_config(share, 10800, "user", "pass")

        stream = cfg["outbounds"][0]["streamSettings"]
        assert stream["httpSettings"]["path"] == "/h2"
        assert stream["httpSettings"]["host"] == ["h2.example.com"]


class TestTrojanConfig:
    def test_basic_tls(self):
        share = _make_share(protocol="trojan", password="secret", security="tls", sni="trojan.example.com")
        cfg = _generate_xray_config(share, 10800, "user", "pass")

        assert cfg["outbounds"][0]["protocol"] == "trojan"
        server = cfg["outbounds"][0]["settings"]["servers"][0]
        assert server["password"] == "secret"

        stream = cfg["outbounds"][0]["streamSettings"]
        assert stream["security"] == "tls"
        assert stream["tlsSettings"]["serverName"] == "trojan.example.com"

    def test_xtls(self):
        share = _make_share(protocol="trojan", password="secret", security="xtls", sni="x.example.com")
        cfg = _generate_xray_config(share, 10800, "user", "pass")

        stream = cfg["outbounds"][0]["streamSettings"]
        assert stream["security"] == "xtls"
        assert "xtlsSettings" in stream

    def test_reality(self):
        share = _make_share(
            protocol="trojan",
            password="secret",
            security="reality",
            sni="r.example.com",
            pbk="pubkey",
            sid="01",
        )
        cfg = _generate_xray_config(share, 10800, "user", "pass")

        stream = cfg["outbounds"][0]["streamSettings"]
        assert stream["security"] == "reality"
        assert stream["realitySettings"]["publicKey"] == "pubkey"
        assert stream["realitySettings"]["serverName"] == "r.example.com"

    def test_ws_transport(self):
        share = _make_share(protocol="trojan", password="s", security="tls", network="ws", path="/ws", host="h.com")
        cfg = _generate_xray_config(share, 10800, "user", "pass")

        stream = cfg["outbounds"][0]["streamSettings"]
        assert stream["wsSettings"]["path"] == "/ws"

    def test_grpc_transport(self):
        share = _make_share(protocol="trojan", password="s", security="tls", network="grpc", service_name="svc")
        cfg = _generate_xray_config(share, 10800, "user", "pass")

        stream = cfg["outbounds"][0]["streamSettings"]
        assert stream["grpcSettings"]["serviceName"] == "svc"

    def test_httpupgrade_transport(self):
        share = _make_share(protocol="trojan", password="s", security="tls", network="httpupgrade", path="/hu")
        cfg = _generate_xray_config(share, 10800, "user", "pass")

        stream = cfg["outbounds"][0]["streamSettings"]
        assert stream["httpupgradeSettings"]["path"] == "/hu"

    def test_splithttp_transport(self):
        share = _make_share(protocol="trojan", password="s", security="tls", network="splithttp", path="/sh")
        cfg = _generate_xray_config(share, 10800, "user", "pass")

        stream = cfg["outbounds"][0]["streamSettings"]
        assert stream["splithttpSettings"]["path"] == "/sh"


class TestShadowsocksConfig:
    def test_basic(self):
        share = _make_share(protocol="ss", method="aes-256-gcm", password="sspass")
        cfg = _generate_xray_config(share, 10800, "user", "pass")

        assert cfg["outbounds"][0]["protocol"] == "shadowsocks"
        server = cfg["outbounds"][0]["settings"]["servers"][0]
        assert server["method"] == "aes-256-gcm"
        assert server["password"] == "sspass"
        assert server["address"] == "example.com"
        assert server["port"] == 443


class TestUnsupportedProtocol:
    def test_unknown_protocol_raises(self):
        share = _make_share(protocol="wireguard")
        with pytest.raises(ValueError, match="Unsupported protocol"):
            _generate_xray_config(share, 10800, "user", "pass")


class TestInboundConfig:
    def test_socks_inbound(self):
        share = _make_share()
        cfg = _generate_xray_config(share, 10800, "user", "pass")

        inbound = cfg["inbounds"][0]
        assert inbound["port"] == 10800
        assert inbound["listen"] == "127.0.0.1"
        assert inbound["protocol"] == "socks"
        assert inbound["settings"]["accounts"][0]["user"] == "user"
        assert inbound["settings"]["accounts"][0]["pass"] == "pass"
        assert inbound["settings"]["udp"] is True

    def test_sniffing_with_fakedns(self):
        share = _make_share()
        cfg = _generate_xray_config(share, 10800, "user", "pass")

        sniffing = cfg["inbounds"][0]["sniffing"]
        assert sniffing["enabled"] is True
        assert "fakedns+others" in sniffing["destOverride"]
        assert sniffing["routeOnly"] is True

    @patch("xray_analyzer.diagnostics.xray_manager.settings")
    def test_sniffing_without_fakedns(self, mock_settings):
        mock_settings.xray_fakedns_enabled = False
        share = _make_share()
        cfg = _generate_xray_config(share, 10800, "user", "pass")

        sniffing = cfg["inbounds"][0]["sniffing"]
        assert sniffing["destOverride"] == ["http", "tls"]
        assert "fakedns" not in cfg  # No fakedns section

    def test_fakedns_config_section(self):
        share = _make_share()
        cfg = _generate_xray_config(share, 10800, "user", "pass")

        assert "fakedns" in cfg
        assert cfg["fakedns"][0]["ipPool"] == "198.18.0.0/15"
        assert cfg["dns"]["servers"] == ["fakedns"]
