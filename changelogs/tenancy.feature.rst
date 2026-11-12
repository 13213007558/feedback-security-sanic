Add request-level tenant leases (``sanic.extensions.tenancy``)

Introduce ``Request.add_finalizer`` so extensions can guarantee cleanup on
success, error and cancellation, and build a tenant borrow contract that keeps
the shared physical resource while freezing each request's identity. Releasing
a lease is reference counted per authorization, so returning one request never
clears authorization still in use by another.
