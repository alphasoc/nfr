# ceflog

> Common Event Format Logger

## about

The ArcSight Common Event Format (CEF) can be used to emit audit logs in a
format which threat analysis and monitoring tools are able to ingest. There
doesn't seem to be a de-facto specification online for CEF but if you search
for *CEF log* you will find redistributions.

## usage

The library is modeled as a logger rather than a sink which can be plugged into
other logging libraries. This is because you only want to log audit-worthy
events rather than logging everything. This would typically be tuned by
adjusting the level (debug, info, warn, error, etc.) of a log message. This
will not work in this case because some of the audit events you want to emit
are not errors.

This library does not append syslog headers onto the message. You should ensure
that your syslog forwarder adds these.

```go
logger := ceflog.New(w, "vendor", "product", "version")

logger.LogEvent(
    "auth.new",
    "User login",
    ceflog.Sev(0),
    ceflog.Ext("dst", "127.0.0.1"),
)
```

More complete documentation can be found in the [GoDoc][godoc].

[godoc]: https://godoc.org/github.com/xoebus/ceflog
