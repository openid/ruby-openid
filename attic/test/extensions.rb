require "test/unit"

require "openid/extensions"
require "openid/sreg"
require "openid/util"

class UtilTestCase < Test::Unit::TestCase

  def test_sreg 
    secret = 'foo'
    openid_sig = 'xxx'

    ext_content = "openid.sig:xxx\nsreg.dob:0000-00-00\nsreg.email:foo@bar.com\n"
    ext_sig = OpenID::Util.to_base64(OpenID::Util.hmac_sha1(secret, ext_content))    
    query = {
      'openid.sig' => openid_sig,
      'sreg.email' => 'foo@bar.com',
      'sreg.dob' => '0000-00-00',
      'sreg.sig' => ext_sig
    }

    sreg = OpenID::SREG.create(secret, query)
    assert_not_nil(sreg)
    assert_equal(ext_content, sreg.ext_content)
    assert_equal(ext_sig, sreg.gen_sig)
    assert_equal(true, sreg.check_sig)
    assert_equal(true, OpenID::SREG.check(secret, query))
  end

end
