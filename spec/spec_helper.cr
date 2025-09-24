require "spec"
require "../src/srp"

def pad_hex_string(str)
  str.size.odd? ? "0#{str}" : str
end