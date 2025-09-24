# srp.cr

A Crystal implementation of the Secure Remote Password (SRP-6a) protocol for secure password-based authentication.

## Overview

SRP is a cryptographic protocol that allows a client to authenticate with a server using a password without ever transmitting the password or password-equivalent data over the network. This implementation follows RFC 5054 and provides both client and server (verifier) components.

## Features

- Complete SRP-6a protocol implementation
- Support for multiple group sizes (1024, 1536, 2048, 3072, 4096, 6144, 8192 bits)
- RFC 5054 compliant
- Zero-knowledge password proof
- No passwords transmitted over the network
- Protection against replay attacks
- Generates strong session keys for subsequent encryption

## Installation

1. Add the dependency to your `shard.yml`:

   ```yaml
   dependencies:
     srp:
       github: wyhaines/srp.cr
   ```

2. Run `shards install`

## Usage

```crystal
require "srp"

# Registration Phase (run once per user)
client = Srp::Client.new
registration = client.register("alice", "password123")
# Store registration[:verifier] and registration[:salt] on server
# Never store the password!

# Authentication Phase
# Client side
client = Srp::Client.new
client.setup_authentication("alice")
client_public_key = client.client_public_key

# Server side
server = Srp::Verifier.new
challenge = server.generate_challenge(
  "alice",
  registration[:verifier],
  registration[:salt],
  client_public_key
)

# Client generates proof
client_proof = client.generate_proof(
  "alice",
  "password123",
  challenge[:salt],
  challenge[:server_public]
)

# Server verifies and responds
server_result = server.verify_proof(client_proof)
if server_result
  # Authentication successful
  server_proof = server_result[:proof]
  session_key = server_result[:key]
end

# Client verifies server
if client.verify_server_proof(server_proof)
  # Mutual authentication complete
  # Both parties now share session_key
end
```

See `example.cr` for a complete working example.

## Development

Run tests with:

```bash
crystal spec
```

Run the example:

```bash
crystal run example.cr
```

## Contributing

1. Fork it (<https://github.com/your-github-user/srp/fork>)
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create a new Pull Request

## Contributors

- [Kirk Haines](https://github.com/your-github-user) - creator and maintainer
