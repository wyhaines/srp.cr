require "./spec_helper"

describe BigInt do
  it "can calculate mod exponents of a BigInt" do
    BigInt.new(2).mod_exp(2, 16).should eq 4
    BigInt.new(2).mod_exp(4, 15).should eq 1
    BigInt.new(2).mod_exp(8, 512).should eq 256
    BigInt.new(2).mod_exp(88888888, 16).should eq 0
    BigInt.new(2).mod_exp(BigInt.new(Srp::Ng::RFC5054_1024, 16), 3).should eq 2
    BigInt.new(2).mod_exp(BigInt.new(Srp::Ng::RFC5054_1024, 16), 100).should eq 88
    BigInt.new(2).mod_exp(BigInt.new(Srp::Ng::RFC5054_1024, 16), 1000).should eq 888
    BigInt.new(2).mod_exp(BigInt.new(Srp::Ng::RFC5054_8192, 16), 100).should eq 88
    BigInt.new(2).mod_exp(BigInt.new(Srp::Ng::RFC5054_8192, 16), 1000).should eq 488
  end
end
