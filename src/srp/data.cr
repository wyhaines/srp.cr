module Srp
  class Data
    # Protocol parameters
    property prime_modulus : BigInt = BigInt.new        # Large safe prime number used as the modulus for all calculations
    property generator : Int32 = 0                       # Generator value for the prime modulus group
    property multiplier_parameter : BigInt = BigInt.new  # Security parameter derived from hash of prime and generator

    # Client-side values
    property client_private_key : BigInt = BigInt.new    # Client's randomly generated secret for this session
    property client_public_key : String = ""             # Client's public key sent to server

    # Server-side values
    property server_private_key : BigInt = BigInt.new    # Server's randomly generated secret for this session
    property server_public_key : String = ""             # Server's public key that includes password verifier

    # Shared values
    property scrambling_parameter : BigInt = BigInt.new  # Prevents replay attacks, derived from both public keys
    property shared_secret : BigInt = BigInt.new         # The shared secret both sides compute independently
    property session_key : String = ""                   # Encryption key derived from the shared secret
    property client_proof : String = ""                  # Client's proof that they know the password
    property server_proof : String = ""                  # Server's proof that they computed the same session key

    # User data
    property hash_algorithm : String = ""                # Hash algorithm to use (SHA1, SHA256, etc)
    property password_verifier : BigInt = BigInt.new     # One-way hash of password stored on server (never the password itself)
    property salt : String = ""                          # Random salt unique to this user
    property username : String = ""                      # User's identity/username
  end
end