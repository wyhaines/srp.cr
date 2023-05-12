# srp.cr
This is a pure Crystal implementation of the Secure Remote Password protocol. With this, a server can validate a secret from a client, such as a password, without ever seeing the secret. The secret itself is never sent over the wire, and the server never stores anything that can be decrypted back into the secret.
