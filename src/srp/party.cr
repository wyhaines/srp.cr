require "./calculations"

module Srp
  class Party
    include Srp::Calculations

    property data : Data

    def initialize(group = 2048)
      @data = Data.new
      @data.n_prime, @data.g, @data.hash = Srp::Ng.parameters_for_group(group)
      @data.k = calc_k(@data.n_prime, @data.g, @data.hash)
    end

    # Generate the verifier, and return a tuple containing the userid, verifier, and salt.
    def register(userid, secret, salt = Random::Secure.random_bytes(16).hexstring)
      key = from_hex_string(calc_x(userid, secret, salt))
      {
        userid: userid,
        verifier: to_hex_string(calculate_verifier(key, @data.n_prime, @data.g)),
        salt: salt,
      }
    end

  end
end
