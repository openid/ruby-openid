require 'test/unit'
require 'yadis/xrds'

class XRDSTestCase < Test::Unit::TestCase

  def test_xrds_good
    File.open('data/brian.xrds') do |f|
      xrds = XRDS.new(f.read)
      assert_not_nil(xrds)
      assert_equal(xrds.services.length, 1)      
    end

    File.open('data/brianellin.mylid.xrds') do |f|
      xrds = XRDS.new(f.read)
      assert_not_nil(xrds)
      assert_equal(xrds.services.length, 9)

      service = xrds.services[0]
      assert_not_nil(service)
      assert_not_nil(service.uri)
    end
  end

  def test_xrds_good_multi
    File.open('data/brian.multi.xrds') do |f|
      xrds = XRDS.new(f.read)
      assert_not_nil(xrds)
      assert_equal(1, xrds.services.length)      
      s = xrds.services[0]
      assert s.service_types.member?('http://openid.net/signon/1.0')
    end
  end

  def test_xrds_good_uri_multi
    File.open('data/brian.multi_uri.xrds') do |f|
      xrds = XRDS.new(f.read)
      assert_not_nil(xrds)
      assert_equal(2, xrds.services.length)
    end
  end

  # This is like brian.multi, but uses namespaces a little differently.
  def test_xrds_good_namespaces
    File.open('data/proxy-june1.xrds') do |f|
      xrds = XRDS.new(f.read)
      assert_not_nil(xrds)
      assert_equal(3, xrds.services.length)
    end
  end

  def test_xrds_unknown_xrd_version
    File.open('data/weirdver.xrds') do |f|
      xrds = XRDS.parse(f.read)
      assert_nil(xrds)
    end
 end

  def test_xrds_bad
    assert_nil(XRDS.parse(nil))
    assert_nil(XRDS.parse(5))
    assert_nil(XRDS.parse(''))
    assert_nil(XRDS.parse('<html></html>'))
    assert_nil(XRDS.parse('\000'))
  end

  def test_marshal
    File.open('data/brian.xrds') do |f|
      xrds = XRDS.new(f.read)
      s = Marshal.dump(xrds)
      xrds2 = Marshal.load(s)
      assert_equal(xrds.services, xrds2.services)
    end   
  end

end
