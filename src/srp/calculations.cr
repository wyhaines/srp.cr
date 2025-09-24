require "openssl"

module Srp
  # The `Calculations` module encapsulates all of the shared convenience methods
  # and mathematical calculation methods that both the client and the server
  # may depend on to perform their respective parts of the SRP-6a protocol.
  module Calculations
    def pad_hex_string(str)
      str.size.odd? ? "0#{str}" : str
    end

    def to_hex_string(number)
      pad_hex_string number.to_s(16).downcase
    end

    def from_hex_string(hexstr)
      BigInt.new(hexstr, 16)
    end

    def calculate_sha(*args)
      hasher = OpenSSL::Digest.new(@data.hash_algorithm)
      args.each {|arg| hasher << arg.to_s}
      hasher.hexfinal
    end

    def calculate_sha(&)
      hasher = OpenSSL::Digest.new(@data.hash_algorithm)
      yield(hasher)
      hasher.hexfinal
    end

    def calculate_hash(*args)
      length = 2 * ((@data.prime_modulus.to_s(16).size * 4 + 7) >> 3)

      hash = calculate_sha do |hasher|
        args.each do |arg|
          arg = (arg.is_a?(String) ? arg : arg.to_s(16)).rjust(length, '0')
          raise ArgumentError.new("The bit width of argument \"#{arg}\" is larger than the allowed bit width of #{length}.") if arg.size > length

          hasher << arg
        end
      end

      BigInt.new(hash, 16) % @data.prime_modulus
    end

    def calculate_multiplier_parameter(prime, generator, hash_class)
      calculate_hash(prime, generator)
    end

    def generate_client_public_key(generator, client_private, prime)
      BigInt.new(generator).mod_exp(client_private, prime)
    end

    # H(salt || H(username || ':' || password))
    def derive_password_hash(username, password, salt)
      calculate_sha do |hasher|
        hasher << (salt.size.odd? ? "0" : "")
        hasher << salt.to_s
        hasher << calculate_sha(username, ":", password)
      end
    end

    def generate_password_verifier(password_hash, prime, generator)
      BigInt.new(generator).mod_exp(password_hash, prime)
    end

    def generate_server_public_key(multiplier, verifier, generator, server_private, prime)
      (multiplier * verifier + BigInt.new(generator).mod_exp(server_private, prime)) % prime
    end

    def calculate_scrambling_parameter(client_public, server_public, prime)
      calculate_hash(client_public, server_public)
    end

    # Calculate shared secret on client side
    # The client removes the password verifier component from server's public key,
    # then raises the result to a combined exponent based on their private key and password
    # Mathematical formula: shared_secret = (server_public - multiplier * generator^password_hash) ^ (client_private + scrambler * password_hash) mod prime
    def calculate_client_shared_secret(server_public, multiplier, generator, password_hash, client_private, scrambler, prime) : BigInt
      # Remove password verifier component from server's public key
      base = from_hex_string(server_public) - (multiplier * BigInt.new(generator).mod_exp(password_hash, prime))
      base = base % prime
      base = prime + base if base < 0

      # Raise to combined exponent
      exponent = client_private + scrambler * password_hash
      base.mod_exp(exponent, prime)
    end

    # Calculate shared secret on server side
    # The server combines client's public key with the password verifier raised to the scrambler,
    # then raises the result to the server's private key
    # Mathematical formula: shared_secret = (client_public * verifier^scrambler) ^ server_private mod prime
    def calculate_server_shared_secret(client_public, verifier, scrambler, server_private, prime) : BigInt
      # Combine client's public key with password verifier raised to scrambler
      base = from_hex_string(client_public) * verifier.mod_exp(scrambler, prime)
      (base % prime).mod_exp(server_private, prime)
    end

    def derive_session_key(shared_secret)
      to_hex_string(BigInt.new(calculate_sha(to_hex_string(shared_secret)), 16))
    end

    # Generate client's proof of password knowledge
    # This proves the client knows the password without sending it
    # Combines hashed protocol parameters with session data for a unique proof
    def generate_client_proof(prime, generator, username, salt, client_public, server_public, session_key)
      # XOR the hashes of prime and generator for added security
      prime_hash = BigInt.new(calculate_sha(to_hex_string(prime)), 16)
      generator_hash = BigInt.new(calculate_sha(to_hex_string(BigInt.new(generator))), 16)
      xor_hash = to_hex_string(prime_hash ^ generator_hash)
      username_hash = calculate_sha(username)

      calculate_sha(xor_hash, username_hash, salt, client_public, server_public, session_key)
    end

    def generate_server_proof(client_public, client_proof, session_key)
      calculate_sha(client_public, client_proof, session_key)
    end
  end
end
