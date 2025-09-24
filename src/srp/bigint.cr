require "big"

struct BigInt
  # :nodoc:
  private def digits_of_n(n, b)
    digits = Array(typeof(n)).new
    while n > 0
      digits << (n % b)
      n //= b
    end
    digits
  end

  # Performing modulo exponentiation on a BigInt can easily overflow the GMP library's
  # ability to handle the number, when one is working with, for example, raising 2 to
  # the power of a 2048 bit prime number before taking the modulo.  This method will
  # quickly and accurately calculate the modulo exponentiation without overflowing or
  # using too much memory.
  #
  # This algorithm is optimized for large exponents.
  #
  # TODO: The actual implementation of the algorithm can likely be optimized.
  def mod_exp(b, n) : BigInt
    base = 2 << 4 # 4 is (k - 1), where k is 5, which seems to give good general performance
    table = Array(BigInt).new(base + 1, 1.to_big_i)
    (1..base).each { |i| table[i] = table[i - 1] * self % n }
    r = 1.to_big_i
    digits_of_n(b, base).reverse.each do |digit|
      5.times { r = r * r % n } # k is 5
      r = r * table[digit] % n if digit > 0
    end
    r
  end
end
