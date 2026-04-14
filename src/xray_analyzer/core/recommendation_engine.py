"""Recommendation engine — analyzes diagnostic results and adds actionable recommendations."""

from ipaddress import ip_address

from xray_analyzer.core.logger import get_logger
from xray_analyzer.core.models import CheckStatus, HostDiagnostic

log = get_logger("recommendation_engine")


class RecommendationEngine:
    """Analyzes cross-proxy test results and adds tailored recommendations."""

    def add_blocking_recommendations(self, diag: HostDiagnostic) -> None:
        """
        Analyze cross-proxy test results to determine blocking type.

        Recommendations are tailored for VPN infrastructure operators,
        focusing on actionable fixes rather than "use another server".
        """
        # Prevent duplicate recommendations
        if diag.recommendations and any(
            "blocked" in r.lower()
            or "unreachable" in r.lower()
            or "throttling" in r.lower()
            or "заблокирован" in r
            or "недоступен" in r
            or "троттлинг" in r.lower()
            for r in diag.recommendations
        ):
            return

        # Extract server domain and resolved IP from diagnostics
        server_domain = "unknown"
        server_ip = None

        for r in diag.results:
            # Get domain from the FIRST Xray connectivity test (domain test)
            if r.check_name.startswith("Proxy Xray Connectivity") and (
                "домен:" in r.check_name or "domain:" in r.check_name
            ):
                sep = "domain:" if "domain:" in r.check_name else "домен:"
                domain_in_label = r.check_name.split(sep)[-1].strip().rstrip(")")
                if domain_in_label:
                    server_domain = domain_in_label
                # Also get server from details if it's a domain (not IP)
                srv = r.details.get("server", "")
                if srv:
                    try:
                        ip_address(srv)
                    except ValueError:
                        server_domain = srv

            # Get resolved IPs from DNS check
            if r.check_name.startswith("DNS Resolution"):
                local_ips = r.details.get("local_ips", [])
                if local_ips and not server_ip:
                    server_ip = local_ips[0]

            # Get IP from Xray IP fallback test
            if r.check_name.startswith("Proxy Xray Connectivity") and "IP:" in r.check_name:
                ip_in_label = r.check_name.split("IP:")[-1].strip().rstrip(")")
                if ip_in_label:
                    try:
                        ip_address(ip_in_label)
                        server_ip = ip_in_label
                    except ValueError:
                        pass
                # Also check details
                srv = r.details.get("server", "")
                if srv:
                    try:
                        ip_address(srv)
                        server_ip = srv
                    except ValueError:
                        pass

        # Extract cross-proxy status
        cross_proxy_result = None
        for r in diag.results:
            if r.check_name.startswith("Xray Cross-Proxy Connectivity"):
                cross_proxy_result = r
                break

        cross_proxy_name = cross_proxy_result.details.get("working_proxy", "") if cross_proxy_result else None
        cross_works = cross_proxy_result and cross_proxy_result.status == CheckStatus.PASS

        # Check 1: DNS Resolution failure — highest priority
        dns_failed = any(
            r.check_name.startswith("DNS Resolution") and r.status == CheckStatus.FAIL for r in diag.results
        )
        if dns_failed:
            diag.add_recommendation(f"🔒 DNS for {server_domain} cannot be resolved or doesn't match Check-Host")
            diag.add_recommendation(
                "Reason: DNS poisoning or geo-blocking — local DNS returns different IPs than external nodes"
            )
            diag.add_recommendation(
                "Solutions:\n"
                "  1) Use public DNS (Google 8.8.8.8, Cloudflare 1.1.1.1)\n"
                "  2) Configure clients to connect by IP directly\n"
                "  3) Change the domain if it's in ISP DNS blocklists"
            )
            return

        # Check 1.5: Xray connectivity passed but Exit IP/SNI failed
        xray_connectivity_passed = any(
            r.check_name.startswith("Proxy Xray Connectivity") and r.status == CheckStatus.PASS for r in diag.results
        )
        exit_ip_failed = any(
            r.check_name.startswith("Proxy Exit IP") and r.status in (CheckStatus.FAIL, CheckStatus.TIMEOUT)
            for r in diag.results
        )
        sni_failed = any(
            r.check_name.startswith("Proxy SNI") and r.status in (CheckStatus.FAIL, CheckStatus.TIMEOUT)
            for r in diag.results
        )

        if xray_connectivity_passed and (exit_ip_failed or sni_failed):
            failed_services = []
            if exit_ip_failed:
                failed_services.append("Exit IP check")
            if sni_failed:
                failed_services.append("SNI check")
            diag.add_recommendation(f"⚠️ Server {server_domain} connects but cannot reach external services")
            diag.add_recommendation(
                f"Reason: Xray connected (HTTP 204) but {', '.join(failed_services)} failed — "
                f"server cannot reach api.ipify.org or other external hosts"
            )
            diag.add_recommendation(
                "Solutions:\n"
                "  1) Check routing and firewall on the server\n"
                "  2) Make sure the server has internet access\n"
                "  3) Check DNS settings on the server (resolv.conf)\n"
                "  4) Server may be behind NAT without external access"
            )
            return

        # Check 2: RKN Throttle — only if Xray connectivity also failed
        xray_connectivity_failed = any(
            r.check_name.startswith("Proxy Xray Connectivity") and r.status in (CheckStatus.FAIL, CheckStatus.TIMEOUT)
            for r in diag.results
        )

        for r in diag.results:
            if not r.check_name.startswith("RKN Throttle"):
                continue
            if r.status not in (CheckStatus.FAIL, CheckStatus.TIMEOUT):
                continue
            if not xray_connectivity_failed:
                continue

            bytes_received = r.details.get("total_bytes_received", r.details.get("bytes_received", 0))

            if bytes_received == 0:
                ip_str = f"IP {server_ip}" if server_ip else server_domain
                if cross_works:
                    diag.add_recommendation(f"🔒 {ip_str} is blocked for direct connections")
                    diag.add_recommendation(
                        f"Reason: 0 bytes received, but works via {cross_proxy_name} — "
                        f"server is functional, only direct connections are blocked"
                    )
                else:
                    diag.add_recommendation(f"🚫 {ip_str} is blocked by RKN")
                    diag.add_recommendation("Reason: 0 bytes received — server not responding to requests")
                diag.add_recommendation(
                    "Solutions:\n"
                    "  1) Change the server IP to a new one from a different subnet\n"
                    "  2) Bridge through a working proxy"
                )
            else:
                kb_received = bytes_received / 1024
                diag.add_recommendation(f"🐌 Server {server_domain} — DPI throttling ({kb_received:.0f}KB cutoff)")
                diag.add_recommendation(
                    f"Reason: RKN drops connection after ~{kb_received:.0f}KB — "
                    "typical DPI filter pattern (TLS ClientHello/SNI)"
                )
                diag.add_recommendation(
                    "Solutions:\n"
                    "  1) Enable transport obfuscation (XHTTP/GRPC/WebSocket)\n"
                    "  2) Use VLESS + Reality with selfsteal certificate\n"
                    "  3) Configure TLS fingerprint to mimic normal web traffic (ja3)\n"
                    "  4) Connect through a working proxy bridge"
                )
            return

        # Analyze cross-proxy Xray connectivity results
        xray_domain_result = None
        xray_ip_result = None

        for r in diag.results:
            if r.check_name.startswith("Proxy Xray Connectivity") and (
                "домен:" in r.check_name or "domain:" in r.check_name
            ):
                xray_domain_result = r
            elif r.check_name.startswith("Proxy Xray Connectivity") and "IP:" in r.check_name:
                xray_ip_result = r

        if not xray_domain_result or not cross_proxy_result:
            return

        if xray_domain_result.status == CheckStatus.PASS:
            return

        cross_status = cross_proxy_result.status

        # Case 3: Direct FAIL + IP FAIL + Cross PASS
        if (
            xray_domain_result.status in (CheckStatus.FAIL, CheckStatus.TIMEOUT)
            and (xray_ip_result is None or xray_ip_result.status in (CheckStatus.FAIL, CheckStatus.TIMEOUT))
            and cross_status == CheckStatus.PASS
        ):
            ip_str = f"IP {server_ip}" if server_ip else server_domain
            diag.add_recommendation(f"🔒 {ip_str} is blocked for direct connections")
            diag.add_recommendation(
                f"Reason: cannot connect directly, but works via {cross_proxy_name} — "
                f"server is functional, blocked for our subnet"
            )
            diag.add_recommendation(
                "Solutions:\n"
                "  1) Bridge through a working proxy to the server\n"
                "  2) Change the server IP to a new one from a different subnet"
            )
            return

        # Case 4: Direct (domain) FAIL + Direct (IP) PASS
        if (
            xray_domain_result.status in (CheckStatus.FAIL, CheckStatus.TIMEOUT)
            and xray_ip_result
            and xray_ip_result.status == CheckStatus.PASS
        ):
            diag.add_recommendation(f"🔒 Domain {server_domain} is blocked (DNS/SNI)")
            diag.add_recommendation(
                f"Reason: cannot connect by domain, but works by IP ({xray_ip_result.details.get('server', '')})"
            )
            diag.add_recommendation(
                "Solutions:\n"
                "  1) Replace the domain with a new one in server configuration\n"
                "  2) Configure clients to connect by IP instead of domain\n"
                "  3) Use SNI obfuscation or selfsteal certificate"
            )
            return

        # Case 5: Direct FAIL + Cross FAIL
        if (
            xray_domain_result.status in (CheckStatus.FAIL, CheckStatus.TIMEOUT)
            and (xray_ip_result is None or xray_ip_result.status in (CheckStatus.FAIL, CheckStatus.TIMEOUT))
            and cross_status in (CheckStatus.FAIL, CheckStatus.TIMEOUT)
        ):
            ip_str = f"IP {server_ip}" if server_ip else server_domain
            diag.add_recommendation(f"🚫 {ip_str} is blocked or server is unreachable")
            diag.add_recommendation(
                f"Reason: not working directly or via {cross_proxy_name} — server is down or globally blocked"
            )
            diag.add_recommendation(
                "Solutions:\n"
                "  1) Check server availability and restart\n"
                "  2) If server is working — change IP to a new one\n"
                "  3) Check Xray config (UUID, ports, certificates)"
            )
            return
