module Srp
  class Verifier < Party

    def generate_challenge_and_proof(userid : String, xverifier : String, xsalt : String, xaa : String)
      return false if (xaa.to_i(16) % @data.n_prime).zero?

      
    end
  end
end
