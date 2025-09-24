require "./spec_helper"

describe "SRP Complete Authentication Flow" do
  it "successfully authenticates with correct password" do
    username = "alice"
    password = "password123"

    client = Srp::Client.new
    registration = client.register(username, password)
    userid = registration[:userid]
    verifier = registration[:verifier]
    salt = registration[:salt]

    client_auth = Srp::Client.new
    client_auth.setup_authentication(username)
    client_a = client_auth.client_public_key

    server = Srp::Verifier.new
    challenge = server.generate_challenge(username, verifier, salt, client_a)
    challenge.should_not be_nil
    server_salt = challenge.not_nil![:salt]
    server_b = challenge.not_nil![:server_public]

    client_proof = client_auth.generate_proof(username, password, server_salt, server_b)
    client_proof.should_not be_nil

    server_result = server.verify_proof(client_proof)
    server_result.should_not be_nil
    server_proof = server_result.not_nil![:proof]
    server_key = server_result.not_nil![:key]

    client_auth.verify_server_proof(server_proof).should be_true

    client_auth.session_key.should eq server.session_key
    client_auth.session_key.should_not eq ""
  end

  it "fails authentication with incorrect password" do
    username = "bob"
    correct_password = "correctpass"
    wrong_password = "wrongpass"

    client = Srp::Client.new
    registration = client.register(username, correct_password)
    verifier = registration[:verifier]
    salt = registration[:salt]

    client_auth = Srp::Client.new
    client_auth.setup_authentication(username)
    client_a = client_auth.client_public_key

    server = Srp::Verifier.new
    challenge = server.generate_challenge(username, verifier, salt, client_a)
    challenge.should_not be_nil
    server_salt = challenge.not_nil![:salt]
    server_b = challenge.not_nil![:server_public]

    client_proof = client_auth.generate_proof(username, wrong_password, server_salt, server_b)

    server_result = server.verify_proof(client_proof)
    server_result.should be_nil

    client_auth.session_key.should_not eq server.session_key
  end

  it "rejects authentication when A mod N = 0" do
    username = "charlie"
    password = "pass"

    client = Srp::Client.new
    registration = client.register(username, password)
    verifier = registration[:verifier]
    salt = registration[:salt]

    server = Srp::Verifier.new
    # A = 0 violates protocol
    challenge = server.generate_challenge(username, verifier, salt, "0")
    challenge.should be_nil
  end

  it "rejects authentication when B mod N = 0 on client side" do
    username = "dave"
    password = "pass"

    client = Srp::Client.new
    client.setup_authentication(username)

    # B = 0 violates protocol
    result = client.process_challenge(username, password, "deadbeef", "0")
    result.should be_nil
  end

  it "works with different group sizes" do
    [1024, 1536, 2048, 3072].each do |group_size|
      username = "user_#{group_size}"
      password = "pass_#{group_size}"

      client = Srp::Client.new(group_size)
      registration = client.register(username, password)
      verifier = registration[:verifier]
      salt = registration[:salt]

      client_auth = Srp::Client.new(group_size)
      client_auth.setup_authentication(username)
      client_a = client_auth.client_public

      server = Srp::Verifier.new(group_size)
      challenge = server.generate_challenge(username, verifier, salt, client_a)
      challenge.should_not be_nil

      server_salt = challenge.not_nil![:salt]
      server_b = challenge.not_nil![:server_public]

      client_proof = client_auth.generate_proof(username, password, server_salt, server_b)

      server_result = server.verify_proof(client_proof)
      server_result.should_not be_nil

      client_auth.verify_server_proof(server_result.not_nil![:proof]).should be_true
      client_auth.session_key.should eq server.session_key
    end
  end
end