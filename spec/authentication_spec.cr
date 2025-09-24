require "./spec_helper"

describe Srp::Client do
  it "can create a properly initialized Client object" do
    client = Srp::Client.new
    client.data.n_prime.should eq BigInt.new(Srp::Ng::RFC5054_2048, 16)
    client.data.g.should eq 2
    client.data.k.should eq BigInt.new("16817246302433857564770528092988484436354560936821251454546448711345809991504")

    client = Srp::Client.new(1024)
    client.data.n_prime.should eq BigInt.new(Srp::Ng::RFC5054_1024, 16)
    client.data.g.should eq 2
    client.data.k.should eq BigInt.new("863924118309370848924897636370553938981705828845")

    client = Srp::Client.new(1536)
    client.data.n_prime.should eq BigInt.new(Srp::Ng::RFC5054_1536, 16)
    client.data.g.should eq 2
    client.data.k.should eq BigInt.new("1150167175349940562803353189122283775347253348557")

    client = Srp::Client.new(2048)
    client.data.n_prime.should eq BigInt.new(Srp::Ng::RFC5054_2048, 16)
    client.data.g.should eq 2
    client.data.k.should eq BigInt.new("16817246302433857564770528092988484436354560936821251454546448711345809991504")

    client = Srp::Client.new(3072)
    client.data.n_prime.should eq BigInt.new(Srp::Ng::RFC5054_3072, 16)
    client.data.g.should eq 5
    client.data.k.should eq BigInt.new("75375587451264059744361784765106746246162431852547325364546181735804709773028")

    client = Srp::Client.new(4096)
    client.data.n_prime.should eq BigInt.new(Srp::Ng::RFC5054_4096, 16)
    client.data.g.should eq 5
    client.data.k.should eq BigInt.new("68637133079007978267080507321788838276025315514540245181452802599994286056385")

    client = Srp::Client.new(6144)
    client.data.n_prime.should eq BigInt.new(Srp::Ng::RFC5054_6144, 16)
    client.data.g.should eq 5
    client.data.k.should eq BigInt.new("64448260342385312275428651710307145661216646493182949837769822903509136309716")

    client = Srp::Client.new(8192)
    client.data.n_prime.should eq BigInt.new(Srp::Ng::RFC5054_8192, 16)
    client.data.g.should eq 19
    client.data.k.should eq BigInt.new("26501635675251767013219576390852620809004214766453251442805122720946319686082")
  end

  it "will setup authentication in the client" do
    client = Srp::Client.new
    client.setup_authentication

    pad_hex_string(client.data.a.to_s(16)).size.should eq 64
    client.data.cap_a.should eq pad_hex_string(BigInt.new(client.data.g).mod_exp(client.data.a, client.data.n_prime).to_s(16))
  end

  it "can generate a verifier in the client" do
    client = Srp::Client.new
    verifier_data = client.register("alice", "eu sao um pato")
    verifier_data[:userid].should eq "alice"
    verifier_data[:salt].size.should eq 32
    verifier_data[:verifier].size.should eq 512
  end
end