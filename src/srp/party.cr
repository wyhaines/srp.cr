require "./calculations"

module Srp
  # Base class for both client and server (verifier) implementations
  # Provides common functionality for the SRP protocol
  class Party
    include Srp::Calculations

    property data : Data

    # Common sizes: 1024, 1536, 2048 (default), 3072, 4096, 6144, 8192
    def initialize(group_size = 2048)
      @data = Data.new
      @data.prime_modulus, @data.generator, @data.hash_algorithm = Srp::Ng.parameters_for_group(group_size)
      @data.multiplier_parameter = calculate_multiplier_parameter(
        @data.prime_modulus,
        @data.generator,
        @data.hash_algorithm
      )
    end

    # Returns the data that should be stored on the server
    def register(username, password, salt = Random::Secure.random_bytes(16).hexstring)
      password_hash = from_hex_string(derive_password_hash(username, password, salt))
      verifier = generate_password_verifier(password_hash, @data.prime_modulus, @data.generator)

      {
        userid: username,
        verifier: to_hex_string(verifier),
        salt: salt,
      }
    end
  end
end
