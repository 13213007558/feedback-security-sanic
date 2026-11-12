# Websockets

Sanic provides an easy to use abstraction on top of [websockets](https://websockets.readthedocs.io/en/stable/).

## Routing

.. column::

    Websocket handlers can be hooked up to the router similar to regular handlers.

.. column::

    ```python
    from sanic import Request, Websocket

    async def feed(request: Request, ws: Websocket):
        pass

    app.add_websocket_route(feed, "/feed")
    ```
    ```python
    from sanic import Request, Websocket

    @app.websocket("/feed")
    async def feed(request: Request, ws: Websocket):
        pass
    ```

## Handler


.. column::

    Typically, a websocket handler will want to hold open a loop.

    It can then use the `send()` and `recv()` methods on the second object injected into the handler.

    This example is a simple endpoint that echos back to the client messages that it receives.

.. column::

    ```python
    from sanic import Request, Websocket

    @app.websocket("/feed")
    async def feed(request: Request, ws: Websocket):
        while True:
            data = "hello!"
            print("Sending: " + data)
            await ws.send(data)
            data = await ws.recv()
            print("Received: " + data)
    ```


.. column::

    You can simplify your loop by just iterating over the `Websocket` object in a for loop.

    *Added in v22.9*

.. column::

    ```python
    from sanic import Request, Websocket

    @app.websocket("/feed")
    async def feed(request: Request, ws: Websocket):
        async for msg in ws:
            await ws.send(msg)
    ```


## Authorization re-confirmation

A websocket keeps the identity confirmed during the handshake. For administrative connections that stay open, that snapshot should not be trusted forever. Sanic provides an authorization generation per account and per-connection state, so the application can re-confirm access and stop new protected actions after a revocation.

```python
from sanic import Request, Websocket
from sanic.exceptions import WebsocketAuthorizationRevoked

@app.websocket("/admin")
async def admin(request: Request, ws: Websocket):
    ws.bind_authorization(account=request.ctx.account)

    async for raw in ws:
        message = decode(raw)
        if message["op"] == "status":
            # Ordinary control messages remain usable after a revocation.
            await ws.send(build_status(ws.authorization_snapshot()))
            continue
        if message["op"] == "reauthorize":
            app.authorize_websocket(request.ctx.account)
            continue

        try:
            # Checked immediately before the protected action executes.
            # ``ws.protected_message()`` combines the read and this check.
            async with ws.protected_action() as receipt:
                await run_admin_action(message)
        except WebsocketAuthorizationRevoked:
            # Sanic has already closed the connection with code 1008.  An
            # action admitted before revocation was allowed to finish and is
            # reported on its receipt; nothing new starts afterwards.
            return
```

`ws.protected_message()` combines both steps: it reads one message through the connection, runs the generation check, and only then yields `(message, receipt)`. Use it when the whole message is protected; use `protected_action()` for smaller actions nested inside a control loop.

`app.authorize_websocket(account)` issues a new generation for the account. Connections still bound to an older generation stop admitting protected actions; `app.revoke_websocket(account)` also marks the account revoked. Two connections for the same account keep separate `authorization_state` objects, so one connection's close decision or in-flight action does not overwrite the other's state.

Application hooks can re-confirm a connection at admission time:

```python
@app.before_server_start
async def configure_reconfirmation(app, _):
    async def revalidate(state):
        # Return a fresh WebsocketAuthorization, a generation int, True to
        # accept the manager's current generation, or False/None to refuse.
        return state.authorization

    app.set_websocket_authorizer(revalidate)
```

The hook is not a substitute for a server-side session store: it runs in the event loop and should read only the application's own authorization authority. A refusal raises `WebsocketAuthorizationRevoked`, closes the connection once (`1008`, "Authorization revoked" by default), and leaves already admitted actions alone. Frame-level receive is not interrupted, so a payload is read before the action gate decides whether it may execute.

## Configuration

See [configuration section](../running/configuration.md) for more details, however the defaults are shown below.

```python
app.config.WEBSOCKET_MAX_SIZE = 2 ** 20
app.config.WEBSOCKET_PING_INTERVAL = 20
app.config.WEBSOCKET_PING_TIMEOUT = 20
```
