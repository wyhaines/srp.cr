require "./party"

module Srp
  # Client-side implementation of SRP protocol
  # Handles password-based authentication from the client's perspective
  class Client < Party
    def setup_authentication(username : String? = nil)
      @data.username = username if username
      @data.client_private_key = BigInt.new(Random::Secure.random_bytes(32).hexstring, 16)
      public_key_value = generate_client_public_key(
        @data.generator,
        @data.client_private_key,
        @data.prime_modulus
      )
      @data.client_public_key = to_hex_string(public_key_value)
    end

    # Returns nil if server's public key is invalid (zero mod prime)
    def process_challenge(username : String, password : String, salt : String, server_public_key : String)
      return nil if (BigInt.new(server_public_key, 16) % @data.prime_modulus).zero?

      @data.username = username
      @data.salt = salt
      @data.server_public_key = server_public_key

      @data.scrambling_parameter = calculate_scrambling_parameter(
        @data.client_public_key,
        @data.server_public_key,
        @data.prime_modulus
      )

      password_hash = from_hex_string(derive_password_hash(username, password, salt))
      @data.shared_secret = calculate_client_shared_secret(
        @data.server_public_key,
        @data.multiplier_parameter,
        @data.generator,
        password_hash,
        @data.client_private_key,
        @data.scrambling_parameter,
        @data.prime_modulus
      )

      @data.session_key = derive_session_key(@data.shared_secret)
    end

    # Can optionally process the challenge in one step if all parameters are provided
    def generate_proof(username : String? = nil, password : String? = nil, salt : String? = nil, server_public_key : String? = nil)
      if username && password && salt && server_public_key
        process_challenge(username, password, salt, server_public_key)
      end

      @data.client_proof = generate_client_proof(
        @data.prime_modulus,
        @data.generator,
        @data.username,
        @data.salt,
        @data.client_public_key,
        @data.server_public_key,
        @data.session_key
      )
      @data.client_proof
    end

    def verify_server_proof(server_proof : String)
      expected_proof = generate_server_proof(
        @data.client_public_key,
        @data.client_proof,
        @data.session_key
      )

      return false unless server_proof == expected_proof

      @data.server_proof = server_proof
      true
    end

    def client_public_key
      @data.client_public_key
    end

    # Alias for backward compatibility
    def client_public
      client_public_key
    end

    def session_key
      @data.session_key
    end
  end
end
