require 'test/unit'
require "openid/association"

class AssociationTestCase < Test::Unit::TestCase

  def test_assoc
    
    issued = Time.now.to_i
    lifetime = 600
    assoc = OpenID::Association.new('handle', 'secret', issued, lifetime,
                                    'HMAC-SHA1')
    s = OpenID::Association.serialize(assoc)
    assert_equal(assoc, OpenID::Association.deserialize(s))    
  end

end

