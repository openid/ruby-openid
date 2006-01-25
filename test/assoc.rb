require 'test/unit'
require "openid/association"

class AssociationTestCase < Test::Unit::TestCase

  def test_assoc
    
    issued = Time.now.to_i
    lifetime = 600
    assoc = OpenID::Association.new('server_url','handle', 'secret',
                                    issued, lifetime)
    s = OpenID::Association.serialize(assoc)
    assert(OpenID::Association.deserialize(s) == assoc)
  end

end

