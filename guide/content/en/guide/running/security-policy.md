---
title: Security policy generations
---

# Security policy generations

Trusted-proxy and authentication settings are security sensitive. Updating
them one field at a time while workers are serving can leave a request using a
mixture of old and new values. A worker could read a new proxy header name but
keep the old proxy count, or accept a token that the currently configured
scheme set no longer covers.

Sanic models these settings as a single immutable policy snapshot with a
generation number. A request resolves exactly one snapshot and keeps it for
its whole lifecycle, so proxy parsing and authentication can never observe
different generations.

## Policy fields

The snapshot covers `FORWARDED_FOR_HEADER`, `FORWARDED_SECRET`,
`PROXIES_COUNT`, `REAL_IP_HEADER`, and the auth settings
`SECURITY_AUTH_REQUIRED`, `SECURITY_AUTH_SCHEMES`, `SECURITY_AUTH_TOKEN`. It
also carries `SECURITY_OLD_CONNECTION_POLICY`.

The defaults are:

```python
app.config.SECURITY_POLICY_ENABLED = False
app.config.SECURITY_AUTH_REQUIRED = False
app.config.SECURITY_AUTH_SCHEMES = ("Bearer", "Token")
app.config.SECURITY_AUTH_TOKEN = None
app.config.SECURITY_OLD_CONNECTION_POLICY = "pin"
```

Validation is complete and atomic. A candidate with an unknown or missing
field, a negative `PROXIES_COUNT`, an empty header name, duplicate schemes, or
`SECURITY_AUTH_REQUIRED=True` without `SECURITY_AUTH_TOKEN` is rejected before
any worker sees it. Exception messages name the field but never include its
value.

## Rollout

A rollout has two phases:

1. Every server worker stages the candidate and acknowledges the generation.
2. Only after every worker has acknowledged does the coordinator send the commit.

The worker keeps the staged candidate apart from the active snapshot. Requests
continue to use the active generation, so a staged candidate is never served.
If an acknowledgement is late, missing, rejected, or a worker exits, the
coordinator sends a rollback to every worker and reports the failed rollout.
A commit failure reverts the workers that already committed.

`SecurityPolicyCoordinator` accepts any channel implementing the
`PolicyChannel` contract. `InMemoryWorkerChannel` is a fake channel for tests
that can delay replies, drop them, or simulate a worker exit at a chosen
point.

```python
from sanic.security import (
    InMemoryWorkerChannel,
    SecurityPolicyCoordinator,
    SecurityPolicySnapshot,
    SecurityPolicyRuntime,
    WorkerEndpoint,
    fields_from_config,
)

initial = SecurityPolicySnapshot.build(0, fields_from_config(app.config))
runtime = SecurityPolicyRuntime(initial, enabled=True, name="worker-1")
channel = InMemoryWorkerChannel()
channel.add_worker(WorkerEndpoint(runtime))
status = SecurityPolicyCoordinator(channel).rollout(
    initial.updated(1, {"PROXIES_COUNT": 1}), attempt=1
)
status.as_dict()
# {"generation": 1, "status": "active",
#  "workers": [{"name": "worker-1", "status": "active"}]}
```

## Old connections

A keep-alive connection is stamped with the generation that accepted it. When
a new generation becomes active, `SECURITY_OLD_CONNECTION_POLICY` decides what
happens on the next request over that connection:

- `pin` (default): the connection keeps using the complete old snapshot. If
  that generation is no longer retained, the request is refused with `503`
  rather than silently mixing fields.
- `revalidate`: the connection re-runs admission under the active snapshot.
  Authentication and proxy fields both move to the new generation together.

New connections always use the active generation.

## Operator output

Operator-facing status contains the generation and lifecycle state only. It
never includes policy values, header names, tokens, or proxy secrets.

```python
app.security_status
# {"generation": 1, "status": "active", ...}
```

The same rule applies to worker acknowledgements: worker state records
`security_generation` and `security_status`, not the snapshot contents. A
server worker that does not confirm an enabled generation is not counted as
running and startup does not complete.

## Scope

The policy governs trusted-proxy parsing and request admission. Application
handlers that inspect `app.config` directly are outside this snapshot and
should use `request.security_policy.fields` when they need the values that
served the current request.
