require "big"

struct BigInt
  # :nodoc:
  @[AlwaysInline]
  private def digits_of_n(n, b)
    digits = Array(typeof(n)).new
    while n > 0
      digits << (n % b)
      n //= b
    end
    digits
  end

  # Determines optimal window size based on exponent bit length
  # Smaller windows for small exponents (less table overhead)
  # Larger windows for large exponents (fewer multiplications)
  @[AlwaysInline]
  private def optimal_window_size_and_base(exponent) : Tuple(Int32, Int32)
    case exponent.bit_length
    when 0..32     then {3, 1 << 3}  # Very small exponents
    when 33..128   then {4, 1 << 4}  # Small exponents
    when 129..512  then {5, 1 << 5}  # Medium exponents (typical SRP range)
    when 513..2048 then {6, 1 << 6}  # Large exponents
    else                {7, 1 << 7}  # Very large exponents
    end
  end

  # Performing modulo exponentiation on a BigInt can easily overflow the GMP library's
  # ability to handle the number, when one is working with, for example, raising 2 to
  # the power of a 2048 bit prime number before taking the modulo.  This method will
  # quickly and accurately calculate the modulo exponentiation without overflowing or
  # using too much memory.
  #
  # This algorithm uses adaptive window sizing based on exponent size.
  def mod_exp(b, n) : BigInt
    k, base = optimal_window_size_and_base(b)

    # Improved table precomputation using doubling strategy
    # Reduces number of full multiplications needed
    table = StaticArray(BigInt, 129).new(1.to_big_i)
    #table = Array(BigInt).new(base + 1, 1.to_big_i)
    table[1] = self % n

    if base > 1
      # Compute self^2 once and reuse
      self_squared = (table[1] * table[1]) % n
      table[2] = self_squared

      # Build remaining entries efficiently
      # Use doubling where possible (powers of 2)
      # For others, use minimal multiplications
      i = 3
      while i <= base
        # For odd entries, multiply previous odd by self^2
        if i.odd?
          table[i] = (table[i - 2] * self_squared) % n
        else
          # For even entries, try to use doubling of half value
          half = i >> 1
          table[i] = (table[half] * table[half]) % n
        end
        i += 1
      end
    end

    r = 1.to_big_i
    digits_of_n(b, base).reverse.each do |digit|
      k.times { r = (r * r) % n }
      r = (r * table[digit]) % n if digit > 0
    end
    r
  end
end
