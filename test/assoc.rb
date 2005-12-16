require 'test/unit'

require "openid/stores"

class AssociationTestCase < Test::Unit::TestCase

  def test_assoc
    
    issued = Time.now.to_i
    lifetime = 600
    assoc = OpenID::ConsumerAssociation.new('server_url','handle', 'secret',
                                            issued, lifetime)
    s = OpenID::ConsumerAssociation.serialize(assoc)
    assert(OpenID::ConsumerAssociation.deserialize(s) == assoc)

  end

end

