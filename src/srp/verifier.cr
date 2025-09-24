require "./party"

module Srp
  # Server-side implementation of SRP protocol (the "Verifier")
  # Handles password verification without storing the actual password
  class Verifier < Party
    # Returns nil if client's public key is invalid (zero mod prime)
    def generate_challenge(username : String, password_verifier : String, salt : String, client_public_key : String)
      return nil if (BigInt.new(client_public_key, 16) % @data.prime_modulus).zero?

      @data.username = username
      @data.salt = salt
      @data.password_verifier = from_hex_string(password_verifier)
      @data.client_public_key = client_public_key

      @data.server_private_key = BigInt.new(Random::Secure.random_bytes(32).hexstring, 16)
      server_public_value = generate_server_public_key(
        @data.multiplier_parameter,
        @data.password_verifier,
        @data.generator,
        @data.server_private_key,
        @data.prime_modulus
      )
      @data.server_public_key = to_hex_string(server_public_value)

      {salt: salt, server_public: @data.server_public_key}
    end

    private def calculate_session_key
      @data.scrambling_parameter = calculate_scrambling_parameter(
        @data.client_public_key,
        @data.server_public_key,
        @data.prime_modulus
      )

      @data.shared_secret = calculate_server_shared_secret(
        @data.client_public_key,
        @data.password_verifier,
        @data.scrambling_parameter,
        @data.server_private_key,
        @data.prime_modulus
      )

      @data.session_key = derive_session_key(@data.shared_secret)
    end

    # Returns server's proof and session key if successful, nil if authentication fails
    def verify_proof(client_proof : String)
      calculate_session_key if @data.session_key.empty?
      expected_proof = generate_client_proof(
        @data.prime_modulus,
        @data.generator,
        @data.username,
        @data.salt,
        @data.client_public_key,
        @data.server_public_key,
        @data.session_key
      )

      return nil unless client_proof == expected_proof

      @data.client_proof = client_proof
      @data.server_proof = generate_server_proof(
        @data.client_public_key,
        @data.client_proof,
        @data.session_key
      )

      {proof: @data.server_proof, key: @data.session_key}
    end

    def session_key
      @data.session_key
    end
  end
end
