require "./src/srp"

# SRP-6a: A Mathematical Walkthrough
#
# This example demonstrates that SRP (and zero-knowledge proofs in general) are
# straightforward mathematics using the same primitives you're familiar with from
# blockchain: modular exponentiation, cryptographic hashing, and the discrete
# logarithm problem.
#
# Nutshell: both parties can compute the same shared secret using
# different paths through the math, but only if one knows the password.

SPACER_WIDTH = 65
puts "SRP-6a Zero-Knowledge Proof Protocol: Mathematical Demonstration"
puts "=" * SPACER_WIDTH
puts

# =============================================================================
# GROUP SIZE SELECTION
# =============================================================================
#
# SRP uses a large prime modulus and a generator. The security comes from
# the computational difficulty of the discrete logarithm problem in this group.
# Larger groups are exponentially harder to break but require more computation.
#
# Available group sizes (all from RFC 5054):
#   - 1024 bits: Legacy, not recommended for new systems (SHA1)
#   - 1536 bits: Marginal security, phase out soon (SHA1)
#   - 2048 bits: Current minimum recommendation (SHA256) - DEFAULT
#   - 3072 bits: Good for sensitive applications (SHA256)
#   - 4096 bits: High security, ~128-bit symmetric equivalent (SHA256)
#   - 6144 bits: Very high security (SHA256)
#   - 8192 bits: Maximum security, ~192-bit symmetric equivalent (SHA256)
#
# For context: Breaking a 1024-bit discrete log is possible with nation-state
# resources. Breaking 2048-bit would require fundamental advances in computing
# or mathematics. Each doubling roughly squares the computational difficulty.

GROUP_SIZE = 1024  # Using small size for readability of output
                   # For production: use 2048 minimum, 3072+ for sensitive data

# Sample user credentials
username = "alice@example.com"
password = "mysecretpassword"

puts "Initial Parameters:"
puts "  Username: #{username}"
puts "  Password: [NEVER TRANSMITTED]"
puts "  Group size: #{GROUP_SIZE} bits"

# Get the actual parameters for this group
temp_client = Srp::Client.new(GROUP_SIZE)
puts "  Generator: #{temp_client.data.generator}"
puts "  Hash algorithm: #{temp_client.data.hash_algorithm}"

# Display the actual prime modulus
prime_hex = temp_client.data.prime_modulus.to_s(16).upcase
puts "  Prime modulus (#{GROUP_SIZE}-bit safe prime from RFC 5054):"
puts "    In hexadecimal (#{prime_hex.size} hex digits):"

prime_hex.chars.each_slice(64) do |slice|
  puts "    #{slice.join}"
end
puts "    Decimal value: #{temp_client.data.prime_modulus}"
puts "    This prime has the special form p = 2q + 1 where q is also prime (safe prime)"
puts
puts "  Security note: We're using #{GROUP_SIZE} bits for demonstration."
puts "  Production systems should use 2048+ bits."
puts

# =============================================================================
# PHASE 1: REGISTRATION (One-time setup when user creates account)
# =============================================================================
puts "─" * SPACER_WIDTH
puts "REGISTRATION PHASE"
puts "─" * SPACER_WIDTH
puts
puts "This happens once when the user creates their account."
puts "The server will store the output, but never see the password."
puts

client_reg = Srp::Client.new(GROUP_SIZE)

# The registration process creates a "verifier" - a one-way transformation of the
# password that can verify someone knows the password without storing it.
registration = client_reg.register(username, password)

puts "1. Generate random salt (prevents rainbow tables):"
puts "   Salt = #{registration[:salt]}"
puts "   Purpose: Even if two users have the same password, their verifiers differ"
puts

puts "2. Derive password hash (one-way function):"
puts "   password_hash = Hash(salt || Hash(username || ':' || password))"
puts "   • First hash: Hash(username || ':' || password) - mixes identity with password"
puts "   • Second hash: Hash(salt || ...) - salts the result"
puts "   • Result: [#{registration[:salt].size * 4}-bit value, never stored or transmitted]"
puts

puts "3. Generate password verifier (another one-way transformation):"
puts "   password_verifier = generator^password_hash mod prime_modulus"
puts "   where generator=#{client_reg.data.generator} (for this group)"
puts "   and prime_modulus is the #{GROUP_SIZE}-bit safe prime shown above"
puts "   Password verifier = #{registration[:verifier][0..40]}..."
puts "   (Full verifier is #{registration[:verifier].size // 2} bytes)"
puts
puts "   What makes this secure:"
puts "   • Given verifier and generator, finding password_hash requires solving the discrete log problem"
puts "   • Given password_hash, finding password requires reversing the hash (impossible)"
puts "   • The verifier is useless without the password"
puts

puts "Server stores: (username, salt, password_verifier)"
puts "Server NEVER stores: password or password_hash"
puts "Attacker who steals database CANNOT directly authenticate"
puts

# =============================================================================
# PHASE 2: AUTHENTICATION (Each time user logs in)
# =============================================================================
puts
puts "─" * SPACER_WIDTH
puts "AUTHENTICATION PHASE"
puts "─" * SPACER_WIDTH
puts
puts "This happens every time the user logs in."
puts "Both parties will prove they know a shared secret without revealing it."
puts "This is the heart of zero-knowledge proofs."
puts

# Step 1: Client generates ephemeral key pair
puts "\nStep 1: Client generates ephemeral values"
puts "  (These change every session, preventing replay attacks)"
puts

client_auth = Srp::Client.new(GROUP_SIZE)
client_auth.setup_authentication(username)

puts "  • Generate random client_private_key (#{client_auth.data.client_private_key.to_s(16).size * 4} bits)"
puts "    This is a cryptographically secure random number, unique to this session"
puts "  • Calculate client_public_key = generator^client_private_key mod prime_modulus"
puts "    Client public key = #{client_auth.client_public_key[0..40]}..."
puts "  • Send to server: (username, client_public_key)"
puts "    Note: Client's public key reveals nothing about the password"
puts

# Step 2: Server generates its ephemeral values and creates challenge
puts "Step 2: Server creates challenge"
puts "  (Server has retrieved stored password_verifier and salt for username)"
puts

server = Srp::Verifier.new(GROUP_SIZE)
challenge = server.generate_challenge(
  username,
  registration[:verifier],
  registration[:salt],
  client_auth.client_public_key
)

if challenge.nil?
  puts "ERROR: Invalid client public key (client_public_key mod prime_modulus = 0)"
  puts "This is a protocol violation check - prevents certain attacks"
  exit 1
end

puts "  • Validate client's public key (check it's not zero mod prime) ✓"
puts "  • Generate random server_private_key (256 bits)"
puts "    Another session-specific random number"
puts "  • Calculate multiplier_parameter = Hash(prime_modulus || generator)"
puts "    Multiplier = #{server.data.multiplier_parameter.to_s(16)[0..20]}..."
puts "    This binds the protocol to the specific group parameters"
puts "  • Calculate server_public_key = (multiplier * password_verifier + generator^server_private_key) mod prime"
puts "    Step by step:"
puts "      1. generator^server_private_key mod prime: Server's ephemeral public key"
puts "      2. multiplier * password_verifier: Added to prevent passive attacks"
puts "      3. Result hides server_private_key while incorporating password_verifier"
puts "    Server public key = #{challenge[:server_public][0..40]}..."
puts "  • Send to client: (salt, server_public_key)"
puts

# Step 3: Both sides compute the same shared secret (if password is correct)
puts "Step 3: Parallel computation of shared secret"
puts "  (This is where the mathematical paths diverge but both converge to the same shared secret)"
puts

# Client side computation
client_auth.process_challenge(username, password, challenge[:salt], challenge[:server_public])

puts "  CLIENT COMPUTATION:"
puts "  • Validate server's public key (check it's not zero mod prime) ✓"
puts "  • Receive (salt, server_public_key) from server"
puts "  • Derive password_hash = Hash(salt || Hash(username || ':' || password))"
puts "    Client recomputes password_hash from the password (server can't do this)"
puts "  • Calculate scrambling_parameter = Hash(client_public_key || server_public_key)"
puts "    Scrambler = #{client_auth.data.scrambling_parameter.to_s(16)[0..40]}..."
puts "    Purpose: Prevents pre-computation attacks, binds this session"
puts "  • Calculate shared_secret:"
puts "    shared_secret = (server_public_key - multiplier * generator^password_hash)^(client_private_key + scrambler * password_hash) mod prime"
puts "    Step by step:"
puts "      1. Calculate multiplier * generator^password_hash: The verifier component in server's key"
puts "      2. Compute server_public_key minus that: Remove verifier, leaving generator^server_private_key"
puts "      3. Calculate client_private_key + scrambler * password_hash: Combine ephemeral and password secrets"
puts "      4. Raise to power: (generator^server_private)^(combined_exponent)"
puts "  • Derive session_key = Hash(shared_secret)"
puts "    Session key = #{client_auth.session_key[0..40]}..."
puts
puts "  SERVER COMPUTATION (happens later when verifying proof):"
puts "  • Will calculate scrambling_parameter = Hash(client_public_key || server_public_key)"
puts "    (Server computes this when it receives client's proof)"
puts "  • Will calculate shared_secret:"
puts "    shared_secret = (client_public_key * password_verifier^scrambler)^server_private_key mod prime"
puts "    Step by step:"
puts "      1. Calculate password_verifier^scrambler: Verifier raised to scrambler"
puts "      2. Compute client_public_key * that: Combine with client's public key"
puts "      3. Since client_public = generator^client_private and verifier = generator^password_hash:"
puts "         Result = generator^(client_private + scrambler * password_hash)"
puts "      4. Raise to server_private_key: Final shared secret"
puts "    Notice: Same result as client if password is correct!"
puts "  • Will derive session_key = Hash(shared_secret)"
puts "    (Server does all this computation when verifying the client's proof)"

# Key insight explanation
puts "\n  THE KEY INSIGHT:"
puts "  Both compute generator^(server_private * (client_private + scrambler * password_hash)) through different paths:"
puts "  • Client: Uses password to remove verifier from server's public key"
puts "  • Server: Uses stored verifier to modify client's public key"
puts "  Only works if client knows the password that generated the verifier"
puts

# Step 4: Client proves it knows the password
puts "\nStep 4: Client proves knowledge of password"
puts "  (Without sending the password, hash, or shared secret)"
puts

client_proof = client_auth.generate_proof()

puts "  • Client computes proof:"
puts "    client_proof = Hash(Hash(prime) XOR Hash(generator) || Hash(username) || salt || client_public || server_public || session_key)"
puts "    This proof includes:"
puts "      - Hash(prime) XOR Hash(generator): Group parameters (prevents substitution attacks)"
puts "      - Hash(username): User identity"
puts "      - salt: Prevents rainbow tables"
puts "      - client_public, server_public: This session's public keys"
puts "      - session_key: The derived encryption key"
puts "    Client proof = #{client_proof[0..40]}..."
puts "  • Send to server: client_proof"
puts "    Note: Proof demonstrates knowledge of session_key without revealing it"
puts

# Step 5: Server verifies client knows the password
puts "\nStep 5: Server verification"

puts "  • Server calculates scrambling_parameter = Hash(client_public || server_public)"
puts "    Scrambler = (same value client computed earlier)"
puts "  • Server calculates shared_secret using stored verifier"
puts "  • Server derives session_key = Hash(shared_secret)"
puts "  • Server computes expected client_proof using its session_key"

server_result = server.verify_proof(client_proof)

if server_result.nil?
  puts "  ✗ AUTHENTICATION FAILED"
  puts "    Server computed different proof, meaning:"
  puts "    - Client used wrong password → different password_hash → different shared_secret → different session_key"
  puts "    - Or protocol was violated (tampering/attack detected)"
  puts
  puts "  What attacker knows: client_public, server_public, client_proof (all useless without password)"
  puts "  What attacker needs: password_hash (requires reversing hash) or discrete log of verifier"
  exit 1
end

puts "  • Server compares client's proof with expected value"
puts "  ✓ AUTHENTICATION SUCCESSFUL - proofs match"
puts "  • Server knows client has correct password"
puts "  • Server generates proof for client: server_proof = Hash(client_public || client_proof || session_key)"
puts "    This proves server had the right verifier and computed same session_key"
puts "    Server proof = #{server_result[:proof][0..40]}..."
puts

# Step 6: Mutual authentication
puts "Step 6: Client verifies server"
if client_auth.verify_server_proof(server_result[:proof])
  puts "  ✓ Server verification successful"
  puts "    Client knows server had the correct password_verifier"
  puts "    Protection against server impersonation"
else
  puts "  ✗ Server verification failed"
  puts "    This server doesn't have the correct verifier!"
  puts "    Could be a man-in-the-middle or fake server"
  exit 1
end

# =============================================================================
# FINAL STATE: Both parties have the same session key
# =============================================================================
puts
puts "─" * SPACER_WIDTH
puts "FINAL RESULT"
puts "─" * SPACER_WIDTH
puts

client_key = client_auth.session_key
server_key = server.session_key

puts "\nShared session keys:"
puts "  Client session_key: #{client_key[0..40]}..."
puts "  Server session_key: #{server_key[0..40]}..."
puts "  Keys match: #{client_key == server_key}"
puts
puts "This key can now be used for symmetric encryption (AES, ChaCha20, etc.) because it can, as shown, only be derived if the client knows the password"
puts

puts "\nWHY THIS IS A ZERO-KNOWLEDGE PROOF:"
puts
puts "1. The password never left the client"
puts "   Not even encrypted - it's never transmitted at all"
puts
puts "2. The server never sees the password"
puts "   Server only stores password_verifier, which can't be reversed to get password"
puts
puts "3. The authentication transcript reveals nothing"
puts "   (client_public, server_public, client_proof, server_proof) are useless without solving discrete log"
puts
puts "4. Computational security"
puts "   Attacker must either:"
puts "   • Solve discrete log of verifier to get password_hash (computationally infeasible)"
puts "   • Reverse hash to get password from password_hash (cryptographically impossible)"
puts "   • Brute force the password (rate-limited by server)"
puts
puts "5. Forward secrecy"
puts "   Each session uses fresh randoms (client_private, server_private)"
puts "   Compromising one session doesn't compromise others"
puts "   Even if password is later revealed, past sessions stay secure"
puts

puts "THE MATH THAT MAKES IT WORK:"
puts
puts "The protocol leverages these mathematical properties:"
puts
puts "1. Discrete Logarithm Problem:"
puts "   Given generator^password_hash mod prime, finding password_hash is computationally hard"
puts "   This protects the password_hash in the password_verifier"
puts
puts "2. Diffie-Hellman Key Exchange:"
puts "   Two parties with secrets can compute a shared value"
puts "   SRP extends this by incorporating the password into the exchange"
puts
puts "3. Modular Arithmetic Properties:"
puts "   (generator^a * generator^b) mod prime = generator^(a+b) mod prime"
puts "   (generator^a)^b mod prime = generator^(a*b) mod prime"
puts "   These let client and server take different paths to same result"
puts
puts "4. Cryptographic Hash Functions:"
puts "   One-way: Can't reverse Hash(x) to get x"
puts "   Avalanche: Small input change → completely different output"
puts "   This protects password and binds session parameters"
puts
puts "This is the same math securing Bitcoin mining (hashes), ECDSA signatures"
puts "(discrete log), and TLS key exchange (Diffie-Hellman). SRP combines these"
puts "proven primitives in a way that achieves zero-knowledge authentication."
puts
puts "The magic of ZK proofs is really just clever algebra with exponentials and modular arithmetic."
puts "ZK proofs involved in proof of identity/humanity, like the SELF protocol,"
puts "are similar in concept to what is demonstrated here, but with more complex math."