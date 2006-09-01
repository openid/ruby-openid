require 'test/unit'
require 'yadis'

# run all the discovery tests from
# http://www.openidenabled.com/resources/yadis-test/discover/manifest.txt
# a local copy of the test data is in data/manifest.txt

class DiscoveryTestCase < Test::Unit::TestCase

  def setup
    @cases = []
    File.open('data/manifest.txt').each_line do |line|
      line.strip!
      if line.index('#') != 0 and line
        @cases << line.split(' ', 3) if line.length > 0
      end
    end

  end

  def test_discovery
    @cases.each_with_index do |x, i|
      input, redir_uri, xrds_uri = x
      y = YADIS.discover(input)
      assert_not_nil(y)
      assert_equal(redir_uri, y.uri)
      assert_equal(xrds_uri, y.xrds_uri)
    end
  end

  def test_bad
    assert_nil(YADIS.discover(nil))
    assert_nil(YADIS.discover(5))

    # not a valid uri
    assert_nil(YADIS.discover('foo.com'))

    # not a yadis uri
    assert_nil(YADIS.discover('http://google.com/?q=huh'))
  end

  def test_marshal
    y = YADIS.discover('http://brian.myopenid.com/')
    Marshal.dump(y)
  end

end
