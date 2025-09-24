require "./spec_helper"

describe Srp::Ng do
  it "returns primes, generator groups, and hash algorithms of the expected sizes and types when using the ng macro" do
    Srp.ng(1024)[0].to_s(16).should eq Srp::Ng::RFC5054_1024.downcase
    Srp.ng(1024)[1].should eq Srp::Ng::RFC5054_1024_G
    Srp.ng(1024)[2].should eq "SHA1"
    Srp.ng(1536)[0].to_s(16).should eq Srp::Ng::RFC5054_1536.downcase
    Srp.ng(1536)[1].should eq Srp::Ng::RFC5054_1536_G
    Srp.ng(1536)[2].should eq "SHA1"
    Srp.ng(2048)[0].to_s(16).should eq Srp::Ng::RFC5054_2048.downcase
    Srp.ng(2048)[1].should eq Srp::Ng::RFC5054_2048_G
    Srp.ng(2048)[2].should eq "SHA256"
    Srp.ng(3072)[0].to_s(16).should eq Srp::Ng::RFC5054_3072.downcase
    Srp.ng(3072)[1].should eq Srp::Ng::RFC5054_3072_G
    Srp.ng(3072)[2].should eq "SHA256"
    Srp.ng(4096)[0].to_s(16).should eq Srp::Ng::RFC5054_4096.downcase
    Srp.ng(4096)[1].should eq Srp::Ng::RFC5054_4096_G
    Srp.ng(4096)[2].should eq "SHA256"
    Srp.ng(6144)[0].to_s(16).should eq Srp::Ng::RFC5054_6144.downcase
    Srp.ng(6144)[1].should eq Srp::Ng::RFC5054_6144_G
    Srp.ng(6144)[2].should eq "SHA256"
    Srp.ng(8192)[0].to_s(16).should eq Srp::Ng::RFC5054_8192.downcase
    Srp.ng(8192)[1].should eq Srp::Ng::RFC5054_8192_G
    Srp.ng(8192)[2].should eq "SHA256"
  end

  it "returns primes, generator groups, and hash algorithms of the expected sizes and types when using the runtime method" do
    Srp::Ng.parameters_for_group(1024)[0].to_s(16).should eq Srp::Ng::RFC5054_1024.downcase
    Srp::Ng.parameters_for_group(1024)[1].should eq Srp::Ng::RFC5054_1024_G
    Srp::Ng.parameters_for_group(1024)[2].should eq "SHA1"
    Srp::Ng.parameters_for_group(1536)[0].to_s(16).should eq Srp::Ng::RFC5054_1536.downcase
    Srp::Ng.parameters_for_group(1536)[1].should eq Srp::Ng::RFC5054_1536_G
    Srp::Ng.parameters_for_group(1536)[2].should eq "SHA1"
    Srp::Ng.parameters_for_group(2048)[0].to_s(16).should eq Srp::Ng::RFC5054_2048.downcase
    Srp::Ng.parameters_for_group(2048)[1].should eq Srp::Ng::RFC5054_2048_G
    Srp::Ng.parameters_for_group(2048)[2].should eq "SHA256"
    Srp::Ng.parameters_for_group(3072)[0].to_s(16).should eq Srp::Ng::RFC5054_3072.downcase
    Srp::Ng.parameters_for_group(3072)[1].should eq Srp::Ng::RFC5054_3072_G
    Srp::Ng.parameters_for_group(3072)[2].should eq "SHA256"
    Srp::Ng.parameters_for_group(4096)[0].to_s(16).should eq Srp::Ng::RFC5054_4096.downcase
    Srp::Ng.parameters_for_group(4096)[1].should eq Srp::Ng::RFC5054_4096_G
    Srp::Ng.parameters_for_group(4096)[2].should eq "SHA256"
    Srp::Ng.parameters_for_group(6144)[0].to_s(16).should eq Srp::Ng::RFC5054_6144.downcase
    Srp::Ng.parameters_for_group(6144)[1].should eq Srp::Ng::RFC5054_6144_G
    Srp::Ng.parameters_for_group(6144)[2].should eq "SHA256"
    Srp::Ng.parameters_for_group(8192)[0].to_s(16).should eq Srp::Ng::RFC5054_8192.downcase
    Srp::Ng.parameters_for_group(8192)[1].should eq Srp::Ng::RFC5054_8192_G
    Srp::Ng.parameters_for_group(8192)[2].should eq "SHA256"
  end
end