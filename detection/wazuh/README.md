# Optional Wazuh adapter

The default Vulnerum demo **does not require Wazuh**. This directory maps the
lab detections into Wazuh's ruleset for teams running `wazuh/wazuh-docker` or a bare
Wazuh manager.

| File | Purpose |
|---|---|
| `local_rules.xml` | Example custom rules (ids 100100–100101) with MITRE ATT&CK tags |

## Install (wazuh/wazuh-docker)

1. Mount the rules file into the manager container:

   ```yaml
   services:
     wazuh.manager:
       volumes:
         - ./detection/wazuh/local_rules.xml:/var/ossec/etc/rules/local_rules.xml:ro
   ```

2. Restart the manager: `docker compose restart wazuh.manager`.

## Install (bare manager)

1. Merge `local_rules.xml` into `/var/ossec/etc/rules/local_rules.xml`.
2. Restart: `systemctl restart wazuh-manager`.

## Validate

Feed a lab log line to `wazuh-logtest` and expect rule **100100** (traversal) or
**100101** (Log4Shell):

```bash
docker compose exec wazuh.manager /var/ossec/bin/wazuh-logtest
# paste: 127.0.0.1 - - [23/Sep/2026:10:00:02 +0000] "GET /icons/.%2e/%2e%2e/etc/passwd HTTP/1.1" 200 1632
```

## Notes

- Rules match the raw log line (`<pcre2>`), so no custom decoder is needed.
- Rule ids ≥ 100000 are the documented custom range — adjust if your deployment differs.
- For richer field mapping, write a decoder for the common log format and switch the
  rules to `<field name="url">` matches (see the Wazuh ruleset XML syntax docs).
