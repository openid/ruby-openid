require 'test/unit'
require 'yadis'

class YADISTestCase < Test::Unit::TestCase

  def test_yadis_lid
    # need an xrds with lid stuff in it for this part
  end

  def test_priority
    xrds = XRDS.parse(File.open('data/brian_priority.xrds').read)    
    assert_equal(2, xrds.services.length)
    assert_equal('http://www.myopenid.com/server', xrds.services[0].uri)
    assert_equal('http://www.schtuff.com/?action=openid_server',
                 xrds.services[1].uri)
  end


end
