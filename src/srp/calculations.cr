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
      hasher = OpenSSL::Digest.new(@data.hash)
      args.each {|arg| hasher << arg.to_s}
      hasher.hexfinal
    end

    def calculate_sha(&)
      hasher = OpenSSL::Digest.new(@data.hash)
      yield(hasher)
      hasher.hexfinal
    end

    def calculate_hash(*args)
      length = 2 * ((@data.n_prime.to_s(16).size * 4 + 7) >> 3)

      hash = calculate_sha do |hasher|
        args.each do |arg|
          arg = (arg.is_a?(String) ? arg : arg.to_s(16)).rjust(length, '0')
          raise ArgumentError.new("The bit width of argument \"#{arg}\" is larger than the allowed bit width of #{length}.") if arg.size > length

          hasher << arg
        end
      end

      BigInt.new(hash, 16) % @data.n_prime
    end

    # Multiplier parameter
    # k = H(N, g)   (in SRP-6a)
    def calc_k(n, g, hash_class)
      calculate_hash(n, g)
    end

    # A = g^a (mod N)
    def calc_cap_a(g, a, n)
      BigInt.new(g).mod_exp(a, n)
    end

    # TODO: Rename this to something less cryptic. What is "x"?
    # Private key (derived from username, raw password and salt)
    # x = H(salt || H(username || ':' || password))
    def calc_x(username, password, salt)
      calculate_sha do |hasher|
        hasher << (salt.size.odd? ? "0" : "")
        hasher << salt.to_s
        hasher << calculate_sha(username, ":", password)
      end
    end

    # Calculate verifier function
    # v = g^x (mod N)
    def calculate_verifier(x, n, g)
      BigInt.new(g).mod_exp(x, n)
    end
  end
end
