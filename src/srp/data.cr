module Srp
  class Data
    property n_prime : BigInt = BigInt.new
    property g : Int32 = 0
    property k : BigInt = BigInt.new
    property a : BigInt = BigInt.new
    property cap_a : String = ""
    # property cap_s
    # property cap_k
    # property cap_m
    # property h_amk
    property hash : String = ""
    property v : BigInt = BigInt.new
  end
end