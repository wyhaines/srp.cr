# SRP (Secure Remote Password) Protocol Implementation
#
# This module provides a complete implementation of the SRP-6a protocol,
# which allows secure password-based authentication without ever sending
# the password over the network.
#
# ## How SRP Works (Simple Explanation)
#
# 1. **Registration**: User creates account with password
#    - Password is hashed and combined with random salt
#    - A "verifier" is generated and stored on server (not the password!)
#
# 2. **Authentication**: User proves they know the password
#    - Client and server exchange public keys
#    - Both compute the same session key (if password is correct)
#    - Client sends proof, server verifies and responds with its proof
#
# 3. **Result**: Both have the same encryption key without sending the password
#
# ## Security Benefits
# - Password never transmitted (even encrypted)
# - Server doesn't store password (only verifier)
# - Immune to replay attacks
# - Forward secrecy (past sessions stay secure if password is compromised)
#
require "./srp/**"