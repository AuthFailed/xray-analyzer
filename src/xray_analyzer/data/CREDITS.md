# Data credits

The bundled asset files in this directory are adapted from external sources.

## `tcp16_targets.json` and `whitelist_sni.txt`

Copied from [Runnin4ik/dpi-detector](https://github.com/Runnin4ik/dpi-detector)
(MIT License), specifically `tcp16.json` and `whitelist_sni.txt` as of
commit `main/2026-03-15`.

Upstream author: Runni ([github.com/Runnin4ik](https://github.com/Runnin4ik)).

Minor sanitization happens at load time (`cdn_target_scanner._normalize_entry`
fixes the `",port"` typo and deduplicates on `(ip, port)`), so the copied
files match upstream byte-for-byte and can be updated via a straight `cp`.

## `dns_servers.json`

Derived from the DNS server lists in dpi-detector's `config.yml` plus a few
well-known public DoH endpoints. The selection of resolvers was shaped by
upstream's choices; we do not claim original work here.

## License

Both sources are MIT-licensed, and we redistribute them under the same terms.
The `LICENSE` file at the repository root governs the rest of this project.
