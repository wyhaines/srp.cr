require "./party"

module Srp
  class Client < Party
    def setup_authentication
      @data.a = BigInt.new(Random::Secure.random_bytes(32).hexstring, 16)
      @data.cap_a = to_hex_string(calc_cap_a(@data.g, @data.a, @data.n_prime))
    end
  end
end
