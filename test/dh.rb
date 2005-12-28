require 'test/unit'

require "openid/dh"
require "openid/util"

# Diffie Hellman test case

class DiffieHellmanTestCase < Test::Unit::TestCase

  def test_dh    
    dh1 = OpenID::DiffieHellman.new
    dh2 = OpenID::DiffieHellman.new
    
    secret1 = dh1.getSharedSecret(dh2.public)
    secret2 = dh2.getSharedSecret(dh1.public)
    assert(secret1 == secret2)
  end

end

