## SAM over TLS/SSL for i2pd

This document describes the design, configuration, and usage of the optional SAM over TLS/SSL feature added to i2pd.

### Overview

- **What it is**: An optional TLS/SSL terminator that accepts encrypted TCP connections from SAM clients and forwards plain TCP to the existing SAM bridge.
- **Where it lives**: Implemented as a small service in `libi2pd_client/SAMSSL.{h,cpp}` and wired from `libi2pd_client/ClientContext.{h,cpp}`.
- **Why**: SAM typically listens on a local address (e.g., 127.0.0.1). This feature allows exposing a secure external endpoint (different address/port) while keeping the original SAM bridge unchanged and local.

### Architecture

- **TLS terminator**: `SAMSslTerminator` uses Boost.Asio and OpenSSL to:
  - Listen on a configured TCP address/port for TLS connections.
  - Perform server-side TLS handshakes using a PEM certificate/key.
  - Connect to the configured backend SAM endpoint (plaintext TCP).
  - Forward data bidirectionally between the TLS socket and the backend SAM socket.
- **Certificate handling**:
  - If the configured certificate or key is missing, a self-signed certificate is generated in the i2pd data directory (similar in spirit to I2PControl).
- **Non-invasive**:
  - The existing `SAMBridge` remains intact. TLS is optional and can be enabled or disabled independently.

### Configuration

All options are in the `[sam]` section of `i2pd.conf`.

Required/typical SAM settings:

```ini
[sam]
address = 127.0.0.1        ; Plain SAM listen address
port = 7656                ; Plain SAM TCP port
; portudp = 7655           ; Optional SAM UDP port
```

Enable the TLS/SSL terminator (optional):

```ini
[sam]
ssl = true                 ; Enable SAM over TLS/SSL (default: false)
ssladdress = 0.0.0.0       ; TLS listen address (empty -> fall back to sam.address)
sslport = 7666             ; TLS listen port (0 disables)
cert = sam.crt.pem         ; PEM certificate path (relative -> i2pd data dir)
key = sam.key.pem          ; PEM private key path (relative -> i2pd data dir)
```

Notes:

- If `ssl = true` and `sslport > 0`, the TLS terminator listens at `ssladdress:sslport` and forwards to `address:port`.
- If `ssladdress` is empty, it defaults to `address`.
- If the cert/key files do not exist, self-signed files are generated.

### Security Considerations

- **Scope of encryption**: TLS protects the client-to-terminator hop. The hop from the terminator to the SAM bridge is plaintext on the local machine.
- **Firewalling**: If you bind the TLS listener to a public address, ensure your firewall policy only allows intended clients.
- **Certificates**: Replace the auto-generated self-signed certificate with your own signed certificate for production deployments.
- **Authentication**: Client certificate authentication is not implemented in this initial version.

### Compatibility

- Existing SAM functionality and configuration remain unchanged.
- The TLS listener is fully optional and disabled by default.

### Logging

- Look for messages prefixed with `Clients: SAM over SSL` and `SAMSSL:` in the logs.
- On first run (missing cert/key), log will indicate certificate creation under the data directory.

### Testing

1) Start i2pd with the TLS listener enabled as shown above.

2) From a client machine, verify the TLS socket is reachable:

```bash
openssl s_client -connect <ssladdress>:<sslport>
```

3) Send a simple SAM handshake to confirm forwarding:

```text
HELLO VERSION MIN=3.0 MAX=3.3\n
```

Expected response includes:

```text
HELLO REPLY RESULT=OK VERSION=3.x
```

If you see this, the TLS terminator and forwarding to the backend SAM are working.

### Limitations and Future Work

- No client certificate (mTLS) support yet.
- No ALPN/SNI-based routing.
- TLS applies to SAM TCP only; SAM UDP is not affected.

### Build & Dependencies

- No extra system dependencies beyond what i2pd already uses (Boost.Asio and OpenSSL).
- The feature is compiled as part of `libi2pdclient` and wired in `ClientContext`.


