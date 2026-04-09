"""Manage Xray core subprocess for VLESS/Trojan/SS proxy testing."""

import asyncio
import json
import tempfile
from contextlib import suppress
from pathlib import Path
from typing import Any

from xray_analyzer.core.config import settings
from xray_analyzer.core.logger import get_logger
from xray_analyzer.diagnostics.subscription_parser import ProxyShareURL

log = get_logger("xray_manager")

# Default local SOCKS port range
_BASE_PORT = 19000


def _generate_xray_config(
    share: ProxyShareURL,
    socks_port: int,
) -> dict[str, Any]:
    """
    Generate Xray JSON config from a share URL.

    Creates an outbound with the proxy config and a local SOCKS inbound.
    """
    # Build outbound based on protocol
    outbound: dict[str, Any] = {
        "protocol": share.protocol if share.protocol != "ss" else "shadowsocks",
        "tag": "proxy",
        "settings": {},
        "streamSettings": {"network": "tcp"},
    }

    if share.protocol == "vless":
        outbound["settings"] = {
            "vnext": [
                {
                    "address": share.server,
                    "port": share.port,
                    "users": [
                        {
                            "id": share.uuid,
                            "flow": share.flow if share.flow else "",
                            "encryption": "none",
                        }
                    ],
                }
            ]
        }

        # Stream settings for VLESS
        stream: dict[str, Any] = {"network": share.network}

        if share.security in ("tls", "reality"):
            if share.security == "reality":
                # REALITY uses realitySettings directly in streamSettings
                stream["realitySettings"] = {
                    "publicKey": share.pbk,
                    "shortId": share.sid,
                    "spiderX": share.spx,
                    "serverName": share.sni or share.host,
                    "fingerprint": share.fp or "chrome",
                }
                if share.sni:
                    stream["realitySettings"]["serverName"] = share.sni
            else:
                # Regular TLS
                tls_settings: dict[str, Any] = {}
                if share.sni:
                    tls_settings["serverName"] = share.sni
                if share.fp:
                    tls_settings["fingerprint"] = share.fp
                stream["tlsSettings"] = tls_settings

            stream["security"] = share.security

        if share.network == "ws":
            stream["wsSettings"] = {
                "path": share.path,
                "headers": {"Host": share.host} if share.host else {},
            }
        elif share.network == "grpc":
            stream["grpcSettings"] = {"serviceName": share.service_name or ""}
        elif share.network == "httpupgrade":
            stream["httpupgradeSettings"] = {
                "path": share.path,
                "host": share.host,
            }
        elif share.network == "http":
            stream["httpSettings"] = {
                "path": share.path,
                "host": [share.host] if share.host else [],
            }

        outbound["streamSettings"] = stream

    elif share.protocol == "trojan":
        outbound["settings"] = {
            "servers": [
                {
                    "address": share.server,
                    "port": share.port,
                    "password": share.password,
                }
            ]
        }

        stream = {"network": share.network}
        if share.security in ("tls", "xtls"):
            tls_settings = {}
            if share.sni:
                tls_settings["serverName"] = share.sni
            if share.fp:
                tls_settings["fingerprint"] = share.fp
            stream["security"] = share.security
            stream["tlsSettings" if share.security == "tls" else "xtlsSettings"] = tls_settings

        if share.network == "ws":
            stream["wsSettings"] = {
                "path": share.path,
                "headers": {"Host": share.host} if share.host else {},
            }
        elif share.network == "grpc":
            stream["grpcSettings"] = {"serviceName": share.service_name or ""}

        outbound["streamSettings"] = stream

    elif share.protocol == "ss":
        outbound["settings"] = {
            "servers": [
                {
                    "address": share.server,
                    "port": share.port,
                    "method": share.method,
                    "password": share.password,
                }
            ]
        }

    else:
        raise ValueError(f"Unsupported protocol for Xray: {share.protocol}")

    config = {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "port": socks_port,
                "listen": "127.0.0.1",
                "protocol": "socks",
                "settings": {
                    "auth": "noauth",
                    "udp": True,
                },
                "sniffing": {
                    "enabled": True,
                    "destOverride": ["http", "tls"],
                },
            }
        ],
        "outbounds": [outbound, {"protocol": "freedom", "tag": "direct"}],
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "rules": [
                {
                    "type": "field",
                    "outboundTag": "proxy",
                    "domain": [
                        "domain:api.ipify.org",
                        "domain:cp.cloudflare.com",
                        "domain:max.ru",
                    ],
                }
            ],
        },
    }

    return config


class XrayInstance:
    """Represents a running Xray core instance."""

    def __init__(self, share: ProxyShareURL) -> None:
        self.share = share
        self.socks_port = 0
        self._process: asyncio.subprocess.Process | None = None
        self._config_path: str | None = None

    async def start(self) -> int:
        """
        Start Xray subprocess with local SOCKS inbound.

        Returns the local SOCKS port number.
        """
        self.socks_port = _BASE_PORT + id(self) % 1000

        config = _generate_xray_config(self.share, self.socks_port)
        log.debug(f"Xray config for {self.share.name}: {json.dumps(config, indent=2)}")

        config_path = Path(tempfile.mktemp(suffix=".json", prefix="xray-config-"))
        self._config_path = str(config_path)
        config_path.write_text(json.dumps(config))

        log.info(
            f"Starting Xray for {self.share.name} "
            f"({self.share.protocol}://{self.share.server}:{self.share.port}) "
            f"on port {self.socks_port}"
        )

        try:
            # Use communicate to capture all output including fast exits
            self._process = await asyncio.create_subprocess_exec(
                settings.xray_binary_path,
                "run",
                "-config",
                self._config_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            # Wait for process to exit or timeout
            try:
                stdout_bytes, stderr_bytes = await asyncio.wait_for(
                    self._process.communicate(),
                    timeout=8,
                )
                stdout_str = stdout_bytes.decode("utf-8", errors="replace").strip()
                stderr_str = stderr_bytes.decode("utf-8", errors="replace").strip()

                # Log all output for debugging
                if stderr_str:
                    log.debug(f"Xray stderr [{self.share.name}]: {stderr_str}")
                if stdout_str:
                    log.debug(f"Xray stdout [{self.share.name}]: {stdout_str}")

                returncode = self._process.returncode or 0
                if returncode != 0:
                    raise RuntimeError(
                        f"Xray exited with code {returncode} for "
                        f"{self.share.name}.\n"
                        f"Stderr: {stderr_str}\n"
                        f"Stdout: {stdout_str}"
                    )

                log.info(f"Xray ready for {self.share.name} on port {self.socks_port}")
                return self.socks_port

            except TimeoutError:
                # Process is still running — it started successfully
                log.info(f"Xray ready for {self.share.name} on port {self.socks_port}")
                return self.socks_port

        except (FileNotFoundError, OSError) as e:
            raise RuntimeError(
                f"Failed to start Xray at '{settings.xray_binary_path}': {e}. "
                "Install Xray core or set XRAY_BINARY_PATH."
            ) from e

    async def stop(self) -> None:
        """Stop the Xray subprocess and clean up config file."""
        if self._process and self._process.returncode is None:
            log.debug(f"Stopping Xray for {self.share.name}")
            try:
                self._process.terminate()
                await asyncio.wait_for(self._process.wait(), timeout=5)
            except TimeoutError:
                self._process.kill()
                await self._process.wait()

        config_file = Path(self._config_path) if self._config_path else None
        if config_file and config_file.exists():
            with suppress(OSError):
                config_file.unlink()

        log.debug(f"Xray stopped for {self.share.name}")
