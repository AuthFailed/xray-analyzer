"""Manage Xray core subprocess for VLESS/Trojan/SS proxy testing."""

import asyncio
import json
import os
import secrets
import socket
import tempfile
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager, suppress
from pathlib import Path
from typing import Any

from xray_analyzer.core.config import settings
from xray_analyzer.core.logger import get_logger
from xray_analyzer.diagnostics.subscription_parser import ProxyShareURL

log = get_logger("xray_manager")


def _next_socks_port() -> int:
    """Grab a free ephemeral port from the OS and return it.

    A small race remains between closing the probe socket and Xray binding,
    but OS-assigned ports avoid collisions under parallel fan-out far better
    than a modulo counter.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _generate_xray_config(
    share: ProxyShareURL,
    socks_port: int,
    socks_user: str,
    socks_password: str,
) -> dict[str, Any]:
    """
    Generate Xray JSON config from a share URL.

    Creates an outbound with the proxy config and a local SOCKS inbound.
    All traffic is routed through the proxy outbound (no routing rules).
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

        stream: dict[str, Any] = {"network": share.network}
        if share.security in ("tls", "xtls"):
            tls_settings: dict[str, Any] = {}
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

    # No routing rules: all traffic goes through the proxy outbound by default.
    # This is correct for all use cases (connectivity checks, cross-proxy tests,
    # throttle checks) — we always want traffic to travel through the proxy.
    config = {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "port": socks_port,
                "listen": "127.0.0.1",
                "protocol": "socks",
                "settings": {
                    "auth": "password",
                    "accounts": [{"user": socks_user, "pass": socks_password}],
                    "udp": True,
                },
                "sniffing": {
                    "enabled": True,
                    "destOverride": ["http", "tls"],
                },
            }
        ],
        "outbounds": [outbound],
    }

    return config


class XrayInstance:
    """Represents a running Xray core instance."""

    def __init__(self, share: ProxyShareURL) -> None:
        self.share = share
        self.socks_port = 0
        self.socks_user = secrets.token_hex(8)
        self.socks_password = secrets.token_hex(16)
        self._process: asyncio.subprocess.Process | None = None
        self._config_fd: int | None = None
        self._config_path: str | None = None

    async def start(self) -> int:
        """
        Start Xray subprocess with local SOCKS inbound.

        Returns the local SOCKS port number.
        """
        self.socks_port = _next_socks_port()

        config = _generate_xray_config(self.share, self.socks_port, self.socks_user, self.socks_password)
        log.debug(f"Xray config for {self.share.name}: {json.dumps(config, indent=2)}")

        # Use mkstemp to safely create a temp file (avoids TOCTOU race)
        fd, config_path = tempfile.mkstemp(suffix=".json", prefix="xray-config-")
        self._config_fd = fd
        self._config_path = config_path
        try:
            os.write(fd, json.dumps(config).encode())
        finally:
            os.close(fd)
            self._config_fd = None

        log.info(
            f"Starting Xray for {self.share.name} "
            f"({self.share.protocol}://{self.share.server}:{self.share.port}) "
            f"on port {self.socks_port}"
        )

        try:
            self._process = await asyncio.create_subprocess_exec(
                settings.xray_binary_path,
                "run",
                "-config",
                self._config_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            # Poll the SOCKS port for readiness (up to 8s with 100ms interval).
            # Xray typically binds within ~500ms, so this is much faster than
            # waiting the full 8s for process.communicate to time out.
            deadline = asyncio.get_running_loop().time() + 8
            while True:
                if self._process.returncode is not None:
                    stdout_bytes = await self._process.stdout.read() if self._process.stdout else b""
                    stderr_bytes = await self._process.stderr.read() if self._process.stderr else b""
                    stdout_str = stdout_bytes.decode("utf-8", errors="replace").strip()
                    stderr_str = stderr_bytes.decode("utf-8", errors="replace").strip()
                    if stderr_str:
                        log.debug(f"Xray stderr [{self.share.name}]: {stderr_str}")
                    if stdout_str:
                        log.debug(f"Xray stdout [{self.share.name}]: {stdout_str}")
                    raise RuntimeError(
                        f"Xray exited with code {self._process.returncode} for "
                        f"{self.share.name}.\n"
                        f"Stderr: {stderr_str}\n"
                        f"Stdout: {stdout_str}"
                    )

                try:
                    _, writer = await asyncio.open_connection("127.0.0.1", self.socks_port)
                    writer.close()
                    with suppress(Exception):
                        await writer.wait_closed()
                    log.info(f"Xray ready for {self.share.name} on port {self.socks_port}")
                    return self.socks_port
                except ConnectionRefusedError, OSError:
                    pass

                if asyncio.get_running_loop().time() >= deadline:
                    raise RuntimeError(
                        f"Xray did not bind SOCKS port {self.socks_port} for {self.share.name} within 8s"
                    )
                await asyncio.sleep(0.1)

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


@asynccontextmanager
async def launched_xray(share: ProxyShareURL) -> AsyncIterator[str]:
    """Start an Xray instance, yield its socks5:// URL, and stop it on exit.

    Use this when you need a temporary Xray tunnel that many parallel tasks
    can share — avoids the N+1 problem of starting a fresh Xray per target.
    """
    xray = XrayInstance(share)
    socks_port = await xray.start()
    try:
        yield f"socks5://{xray.socks_user}:{xray.socks_password}@127.0.0.1:{socks_port}"
    finally:
        await xray.stop()
