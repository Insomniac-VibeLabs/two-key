# Two-Key to Elasticsearch and Kibana, end to end

A local test of the 0.7.0 SIEM copy ([docs/SIEM.md](../../../docs/SIEM.md)): Two-Key sends each ledger
entry over syslog (TLS) or an HTTPS webhook, a small receiver indexes it into Elasticsearch, and Kibana
shows it on a dashboard. Everything listens on loopback and nothing is published.

This is an example, not a deployment. Elasticsearch runs with security off, there is no password, and
the certificates are throwaway. What a collector stores, who may read it, how long it keeps it, and
what it alerts on are yours to decide; Two-Key only hands over the events.

| File | What it is |
| --- | --- |
| `make-certs.sh` | a throwaway CA and a server certificate for 127.0.0.1 and localhost |
| `docker-compose.yml` | Elasticsearch and Kibana, loopback only |
| `receiver.py` | the collector: syslog over TLS and the HTTPS webhook, into `_bulk` |
| `ingest-pipeline.json` | gives every event an `@timestamp` so Kibana can plot it |
| `siem.yaml` | the `siem:` block Two-Key reads |
| `dashboard.ndjson` | a data view, three saved searches, and a dashboard for Kibana |

You need Docker (or Podman) with `compose`, Python 3.10 or later, `openssl`, and `curl`. Run everything
from this folder.

## 1. Certificates, and the stack

```bash
sh make-certs.sh                 # writes tls/ca.pem, tls/server.pem, tls/server.key, tls/token, tls/hmac
docker compose up -d
until curl -fsS http://127.0.0.1:9200/_cluster/health >/dev/null; do sleep 2; done
curl -fsS -X PUT http://127.0.0.1:9200/_ingest/pipeline/two-key-siem \
  -H 'Content-Type: application/json' --data-binary @ingest-pipeline.json
```

## 2. The receiver

In its own terminal:

```bash
python3 receiver.py --cert tls/server.pem --key tls/server.key \
  --webhook-port 8443 --auth-value-file tls/token --hmac-key-file tls/hmac
```

It listens for syslog on 6514 and the webhook on 8443, checks the webhook's `Authorization` header and
`X-Two-Key-Signature`, and indexes into `two-key-siem` through the pipeline. `--print` writes the
events to stdout instead, which is the quickest way to see what leaves Two-Key.

## 3. Send some decisions

The demo signs a constitution, allows one call, denies another, redeems a token, and refuses a replay,
in a temporary ledger:

```bash
python3 -m two_key demo --siem siem.yaml
```

Two-Key prints one line per plaintext sink (none here, the default is TLS) and, at the end, the
refused-token count: the demo uses a token that does not verify on purpose, so you can see

```
two-key: gateway refused 1 token(s) that did not verify in 0 s: malformed=1; no ledger entry (see docs/SIEM.md)
```

That count is the one event with `"ledgered": false`. It is never written to the ledger, so a caller
without a valid token cannot make the ledger grow.

To send your own ledger instead, put the same `siem:` block in `proxy.yaml`, or pass
`SiemConfig(...)` to `TwoKey(...)`, and backfill the history that predates the copy:

```bash
python3 -m two_key siem-export --key keys/principal.pem --ledger ledger --schema ecs --out history.jsonl
python3 -m two_key siem-verify --key keys/principal.pem --ledger ledger --events history.jsonl --require-complete
```

## 4. Look at it

```bash
curl -fsS 'http://127.0.0.1:9200/two-key-siem/_count'
curl -fsS -X POST 'http://127.0.0.1:5601/api/saved_objects/_import?overwrite=true' \
  -H 'kbn-xsrf: true' -F file=@dashboard.ndjson
```

Then open <http://127.0.0.1:5601> and the dashboard **Two-Key: ledger copy**. Its three panels are
denied calls, allowed calls, and the events worth an alert (refused tokens, gateway denies, a witness
rotation, a revocation). If your Kibana refuses the import, the data view alone is enough: make one
for `two-key-siem*` with `@timestamp` as the time field.

What is in a document, with `schema: ecs`: `event.action` (the ledger kind), `event.outcome`,
`event.reason` (the library's reason code), `event.sequence` (the ledger `seq`), `observer.product`,
and the rest under `two_key.*`, including `entry_hash` and the digests. What is not in it: argument
values, proposal text, the derived amount, counterparties, custom field values, scanner threat names,
and anything about a token. `schema: native` keeps Two-Key's own field names, which read more plainly
and need no mapping.

An event sent late — after an outage, or a catch-up at start — carries `two_key.replay: true`, so the
dashboard does not read the send time as the decision time.

## 5. Stop

```bash
docker compose down -v           # and the index is gone with it
rm -rf tls                       # the throwaway certificates
```

## Wazuh, Splunk, and the rest

Any collector that takes RFC 5424 syslog or an HTTPS POST works the same way. Wazuh takes these
messages on its syslog listener (`<remote>` with `connection: syslog`), with `schema: native`; Splunk
takes the webhook at HEC with `auth_header: Authorization` and `auth_value_file` holding
`Splunk <token>`. Neither is tested in CI.

## If something does not arrive

- Two-Key warns at start for a sink it cannot reach and keeps authorizing: the copy waits, the
  decisions do not. Look for `two-key: WARNING: siem` on its stderr.
- A sink that was down resumes from its cursor (`<ledger>.siem/cursor.json`). Delete that file and the
  next start sends from `replay_from` again.
- `transport: udp` can drop events with no error anywhere. TLS is the default for a reason.
- The receiver prints every Elasticsearch refusal it gets. Run it with `--print` to take
  Elasticsearch out of the picture and see whether the events are arriving at all.
