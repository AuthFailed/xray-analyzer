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
            "заблокирован" in r or "недоступен" in r or "троттлинг" in r.lower() for r in diag.recommendations
        ):
            return

        # Extract server domain and resolved IP from diagnostics
        server_domain = "unknown"
        server_ip = None

        for r in diag.results:
            # Get domain from the FIRST Xray connectivity test (domain test)
            if r.check_name.startswith("Proxy Xray Connectivity") and "домен:" in r.check_name:
                domain_in_label = r.check_name.split("домен:")[-1].strip().rstrip(")")
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
            diag.add_recommendation(f"🔒 DNS для {server_domain} не разрешается или не совпадает с Check-Host")
            diag.add_recommendation(
                "Причина: DNS poisoning или geo-blocking — локальный DNS возвращает другие IP, чем внешние ноды"
            )
            diag.add_recommendation(
                "Решения:\n"
                "  1) Использовать публичный DNS (Google 8.8.8.8, Cloudflare 1.1.1.1)\n"
                "  2) Настроить клиентов на подключение по IP напрямую\n"
                "  3) Сменить домен, если он попал в блокировки DNS-провайдеров"
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
            diag.add_recommendation(f"⚠️ Сервер {server_domain} подключается, но не достигает внешних сервисов")
            diag.add_recommendation(
                f"Причина: Xray подключился (HTTP 204), но {', '.join(failed_services)} провалились — "
                f"сервер не может достичь api.ipify.org или других внешних хостов"
            )
            diag.add_recommendation(
                "Решения:\n"
                "  1) Проверить маршрутизацию и firewall на сервере\n"
                "  2) Убедиться что сервер имеет доступ к внешнему интернету\n"
                "  3) Проверить DNS-настройки сервера (resolv.conf)\n"
                "  4) Возможно, сервер находится в NAT без внешнего доступа"
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
                    diag.add_recommendation(f"🔒 {ip_str} заблокирован для прямых подключений")
                    diag.add_recommendation(
                        f"Причина: 0 байт получено, но через {cross_proxy_name} работает — "
                        f"сервер рабочий, только прямые подключения заблокированы"
                    )
                else:
                    diag.add_recommendation(f"🚫 {ip_str} заблокирован РКН")
                    diag.add_recommendation("Причина: 0 байт получено — сервер не отвечает на запросы")
                diag.add_recommendation(
                    "Решения:\n"
                    "  1) Сменить IP-адрес сервера на новый из другой подсети\n"
                    "  2) Прокинуть мост (bridge) через рабочий прокси"
                )
            else:
                kb_received = bytes_received / 1024
                diag.add_recommendation(f"🐌 Сервер {server_domain} — DPI-троттлинг ({kb_received:.0f}KB cutoff)")
                diag.add_recommendation(
                    f"Причина: РКН обрывает соединение после ~{kb_received:.0f}KB — "
                    "типичный паттерн DPI-фильтра (TLS ClientHello/SNI)"
                )
                diag.add_recommendation(
                    "Решения:\n"
                    "  1) Включить обфускацию транспорта (XHTTP/GRPC/WebSocket)\n"
                    "  2) Использовать VLESS + Reality с selfsteal-сертификатом\n"
                    "  3) Настроить TLS fingerprint под обычный веб-трафик (ja3)\n"
                    "  4) Подключаться через рабочий прокси-мост"
                )
            return

        # Analyze cross-proxy Xray connectivity results
        xray_domain_result = None
        xray_ip_result = None

        for r in diag.results:
            if r.check_name.startswith("Proxy Xray Connectivity") and "домен:" in r.check_name:
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
            diag.add_recommendation(f"🔒 {ip_str} заблокирован для прямых подключений")
            diag.add_recommendation(
                f"Причина: не подключается напрямую, но через {cross_proxy_name} работает — "
                f"сервер рабочий, блокировка для нашей подсети"
            )
            diag.add_recommendation(
                "Решения:\n"
                "  1) Прокинуть мост (bridge) через рабочий прокси до сервера\n"
                "  2) Сменить IP-адрес сервера на новый из другой подсети"
            )
            return

        # Case 4: Direct (domain) FAIL + Direct (IP) PASS
        if (
            xray_domain_result.status in (CheckStatus.FAIL, CheckStatus.TIMEOUT)
            and xray_ip_result
            and xray_ip_result.status == CheckStatus.PASS
        ):
            diag.add_recommendation(f"🔒 Домен {server_domain} заблокирован (DNS/SNI)")
            diag.add_recommendation(
                f"Причина: по домену не подключается, но по IP ({xray_ip_result.details.get('server', '')}) проходит"
            )
            diag.add_recommendation(
                "Решения:\n"
                "  1) Заменить домен на новый в конфигурации сервера\n"
                "  2) Настроить клиентов на подключение по IP вместо домена\n"
                "  3) Использовать SNI-обфускацию или selfsteal-сертификат"
            )
            return

        # Case 5: Direct FAIL + Cross FAIL
        if (
            xray_domain_result.status in (CheckStatus.FAIL, CheckStatus.TIMEOUT)
            and (xray_ip_result is None or xray_ip_result.status in (CheckStatus.FAIL, CheckStatus.TIMEOUT))
            and cross_status in (CheckStatus.FAIL, CheckStatus.TIMEOUT)
        ):
            ip_str = f"IP {server_ip}" if server_ip else server_domain
            diag.add_recommendation(f"🚫 {ip_str} заблокирован или сервер недоступен")
            diag.add_recommendation(
                f"Причина: не работает ни напрямую, ни через {cross_proxy_name} — "
                f"сервер выключен или заблокирован глобально"
            )
            diag.add_recommendation(
                "Решения:\n"
                "  1) Проверить доступность сервера и перезапустить\n"
                "  2) Если сервер работает — сменить IP-адрес на новый\n"
                "  3) Проверить Xray-конфиг (UUID, порты, сертификаты)"
            )
            return
