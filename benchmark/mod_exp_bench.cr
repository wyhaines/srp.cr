require "benchmark"
require "../src/srp"

# Test data setup
small_base = BigInt.new(2)
medium_base = BigInt.new(Random::Secure.random_bytes(32).hexstring, 16)
large_base = BigInt.new(Random::Secure.random_bytes(256).hexstring, 16)

# Various prime sizes from RFC 5054
prime_1024 = BigInt.new(Srp::Ng::RFC5054_1024, 16)
prime_2048 = BigInt.new(Srp::Ng::RFC5054_2048, 16)
prime_3072 = BigInt.new(Srp::Ng::RFC5054_3072, 16)
prime_4096 = BigInt.new(Srp::Ng::RFC5054_4096, 16)

# Various exponent sizes (typical for SRP)
small_exp = BigInt.new(Random::Secure.random_bytes(32).hexstring, 16)  # 256-bit
medium_exp = BigInt.new(Random::Secure.random_bytes(128).hexstring, 16) # 1024-bit
large_exp = BigInt.new(Random::Secure.random_bytes(256).hexstring, 16)  # 2048-bit

# Warmup
puts "Warming up..."
3.times do
  small_base.mod_exp(small_exp, prime_1024)
end

puts "\n" + "="*80
puts "BigInt#mod_exp Benchmark Results"
puts "="*80
puts "\nAll times in seconds. Lower is better."
puts "Format: base_size ^ exponent_size mod prime_size"
puts "-"*80

# Benchmark different combinations
test_cases = [
  {name: "Small: 2^256-bit mod 1024-bit", base: small_base, exp: small_exp, mod: prime_1024, iterations: 1000},
  {name: "Small: 2^1024-bit mod 1024-bit", base: small_base, exp: medium_exp, mod: prime_1024, iterations: 1000},
  {name: "Small: 2^2048-bit mod 1024-bit", base: small_base, exp: large_exp, mod: prime_1024, iterations: 500},

  {name: "Medium: 256-bit^256-bit mod 2048-bit", base: medium_base, exp: small_exp, mod: prime_2048, iterations: 500},
  {name: "Medium: 256-bit^1024-bit mod 2048-bit", base: medium_base, exp: medium_exp, mod: prime_2048, iterations: 300},
  {name: "Medium: 256-bit^2048-bit mod 2048-bit", base: medium_base, exp: large_exp, mod: prime_2048, iterations: 200},

  {name: "Large: 2048-bit^256-bit mod 3072-bit", base: large_base, exp: small_exp, mod: prime_3072, iterations: 300},
  {name: "Large: 2048-bit^1024-bit mod 3072-bit", base: large_base, exp: medium_exp, mod: prime_3072, iterations: 200},
  {name: "Large: 2048-bit^2048-bit mod 3072-bit", base: large_base, exp: large_exp, mod: prime_3072, iterations: 100},

  {name: "XLarge: 2048-bit^2048-bit mod 4096-bit", base: large_base, exp: large_exp, mod: prime_4096, iterations: 100},
]

results = [] of NamedTuple(name: String, time_per_op: Float64, ops_per_sec: Float64)

test_cases.each do |test|
  print "\nBenchmarking: #{test[:name]}"
  print " (#{test[:iterations]} iterations)..."

  time = Benchmark.realtime do
    test[:iterations].times do
      test[:base].mod_exp(test[:exp], test[:mod])
    end
  end

  time_per_op = time.total_seconds / test[:iterations]
  ops_per_sec = 1.0 / time_per_op

  results << {name: test[:name], time_per_op: time_per_op, ops_per_sec: ops_per_sec}

  printf("\n  Time per operation: %.6f seconds\n", time_per_op)
  printf("  Operations per second: %.2f\n", ops_per_sec)
end

puts "\n" + "="*80
puts "Summary (sorted by time per operation):"
puts "="*80

results.sort_by! { |r| r[:time_per_op] }
results.each do |result|
  printf("%-50s: %.6fs (%.2f ops/s)\n", result[:name], result[:time_per_op], result[:ops_per_sec])
end

puts "\n" + "="*80
puts "Typical SRP Use Cases:"
puts "="*80

# Specific SRP protocol operations
puts "\nClient generates A = g^a mod N (2048-bit prime):"
g = BigInt.new(2)
a = BigInt.new(Random::Secure.random_bytes(32).hexstring, 16)  # Client's private key
time = Benchmark.realtime do
  100.times { g.mod_exp(a, prime_2048) }
end
printf("  Average time: %.6f seconds\n", time.total_seconds / 100)
printf("  Operations per second: %.2f\n", 100 / time.total_seconds)

puts "\nServer calculates v^u mod N (2048-bit prime):"
v = BigInt.new(Random::Secure.random_bytes(256).hexstring, 16) # Password verifier
u = BigInt.new(Random::Secure.random_bytes(32).hexstring, 16)  # Scrambling parameter
time = Benchmark.realtime do
  100.times { v.mod_exp(u, prime_2048) }
end
printf("  Average time: %.6f seconds\n", time.total_seconds / 100)
printf("  Operations per second: %.2f\n", 100 / time.total_seconds)

puts "\nCompleted benchmark. Compile with --release for production performance."
