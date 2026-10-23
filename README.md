# idor-matrix

Stop testing IDOR one ID at a time. Build the matrix.

Broken object-level authorisation is still the most common high-impact API bug, and the
usual test is a single poke: change `?id=5` to `?id=6`, see a 403, move on. That misses
endpoints, methods and roles — and produces findings you cannot reproduce.

`idor-matrix` makes the grid explicit: **every object endpoint × every object ID × every
account**, with a verdict per cell and a TSV you can attach to a report.

```
$ idor-matrix plan -c config.yaml

target: https://target.example
accounts: alice, bob
endpoints: 3 · requests to send: 36
  invoice              /api/v1/invoices/{id}
  user-profile         /api/v1/users/{id}
  order                /api/v1/orders/{id}

dry run — nothing sent. add --execute to run.
```

```
$ idor-matrix run -c config.yaml --execute -o out.tsv

36 requests -> out.tsv
candidate IDOR: 2
  GET /api/v1/invoices/201  as alice on bob's object (200)
  GET /api/v1/orders/8841   as alice on bob's object (200)

Reminder: a 200 is a candidate, not a finding. Confirm foreign data is real, then report.
```

## Config

```yaml
base_url: https://target.example
accounts:
  alice: { headers: { Authorization: "Bearer <alice>" }, ids: [101, 102] }
  bob:   { headers: { Authorization: "Bearer <bob>"   }, ids: [201, 202] }
endpoints:
  - name: invoice
    path: /api/v1/invoices/{id}
```

IDs per account matter: the tool tests *alice requesting bob's objects*, not random
numbers. A 403 on an ID that never existed proves nothing.

## Verdicts

| Verdict | Meaning |
|---|---|
| `CANDIDATE_IDOR` | cross-account 200 with a body size that differs from the requester's own object |
| `CHECK_SAME_SIZE` | cross-account 200 whose size matches the requester's baseline — could be an empty shell or a real leak, look manually |
| `denied` | 401/403 — the correct behaviour |
| `not_found` | 404, ambiguous (some apps 404 instead of 403) |
| `baseline_ok` / `baseline_NNN` | the requester reading their **own** object; your control row |
| `ERROR` | network failure, recorded not swallowed |

The baseline rows are the part people skip. Without them you cannot tell "200 because
it worked" from "200 because everything returns 200".

## Safety defaults

- **GET only** unless `--allow-write` — and even then, think before pointing it at prod.
- **`--execute` required.** Without it you get the plan, not requests.
- Sequential with `--delay` (default 0.3 s) so you do not become the DoS.
- Every request lands in the TSV, including errors.

Only run this against systems you are authorised to test, inside the agreed scope.

## Install & test

```bash
pip install pyyaml requests
python3 idor_matrix.py plan -c config.yaml
python3 -m unittest discover -s tests -v     # 10 tests, incl. a local fixture server
```

The test suite spins a local HTTP server with one deliberately vulnerable endpoint and
one correct one, and asserts the tool flags the first and not the second.

## Licence

MIT
