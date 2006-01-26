require 'test/unit'
require 'openid/association'

class AssociationTestCase < Test::Unit::TestCase

  def _get_assoc
    issued = Time.now.to_i
    lifetime = 600
    OpenID::Association.new('handle', 'secret', issued, lifetime, 'HMAC-SHA1')
  end

  def test_assoc
    assoc = _get_assoc
    s = OpenID::Association.serialize(assoc)
    assert_equal(assoc, OpenID::Association.deserialize(s))    
  end

  def test_sign
    assoc = _get_assoc

    h = {
      'openid.a' => 'b',
      'openid.c' => 'd',
    }

    assoc.add_signature(['a','c'], h)
    assert_not_nil(h['openid.signed'])
    assert_not_nil(h['openid.sig'])
    assert_equal(h['openid.signed'], 'a,c')
    
    sig = OpenID::Util.to_base64( \
           OpenID::Util.hmac_sha1(assoc.secret, "a:b\nc:d\n"))

    assert_equal(h['openid.sig'], sig)
  end

end

