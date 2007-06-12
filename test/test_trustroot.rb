require 'test/unit'
require 'openid/trustroot'

class TrustRootTestCase < Test::Unit::TestCase

  def test_parse_bad

    def assert_bad(s)
      tr = OpenID::TrustRoot.parse(s)
      assert_nil(tr)
    end

    assert_bad('baz.org')
    assert_bad('*.foo.com')
    assert_bad('http://*.schtuff.*/')
    assert_bad('ftp://foo.com')
    assert_bad('ftp://*.foo.com')
    assert_bad('http://*.foo.com:80:90/')
    assert_bad('foo.*.com')
    assert_bad('http://foo.*.com')
    assert_bad('http://www.*')
    assert_bad('')
    assert_bad(' ')
    assert_bad(' \t\n ')
    assert_bad(nil)
    assert_bad(5)
  end

  def test_parse_good
    
    def assert_good(s)
      tr = OpenID::TrustRoot.parse(s)
      assert_not_nil(tr)
    end

    assert_good('http://*/')
    assert_good('https://*/')
    assert_good('http://*.schtuff.com/')
    assert_good('http://*.schtuff.com')
    assert_good('http://www.schtuff.com/')
    assert_good('http://www.schtuff.com')
    assert_good('http://*.this.that.schtuff.com/')
    assert_good('http://*.com/')
    assert_good('http://*.com')
    assert_good('http://*.foo.com/path')
    assert_good('http://x.foo.com/path?action=foo2')
    assert_good('http://*.foo.com/path?action=foo2')
    assert_good('http://localhost:8081/')
  end

  def test_sane

    def assert_sane(s, expected)
      tr = OpenID::TrustRoot.parse(s)
      assert_not_nil(tr)
      assert_equal(tr.sane?, expected, s)
    end

    assert_sane('http://*/', false)
    assert_sane('https://*/', false)
    assert_sane('http://*.schtuff.com/', true)
    assert_sane('http://*.foo.schtuff.com/', true)
    assert_sane('http://*.com/', false)
    assert_sane('http://*.com.au/', false)
    assert_sane('http://*.co.uk/', false)
    assert_sane('http://localhost:8082/?action=openid', true)
    assert_sane('http://*.foo.notatld', false)
    assert_sane('http://*.museum/', false)
    assert_sane('http://kink.fm/', true)
    assert_sane('http://beta.lingu.no/', true)
  end

  def test_validate
    
    def assert_valid(s, url, expected)
      tr = OpenID::TrustRoot.parse(s)
      assert_not_nil(tr)
      assert_equal(tr.sane?, true)
      assert_equal(tr.validate_url(url), expected)
    end

    assert_valid('http://*.foo.com', 'http://foo.com', true)
    assert_valid('http://*.foo.com/', 'http://foo.com/', true)
    assert_valid('http://*.foo.com', 'http://b.foo.com', true)
    assert_valid('http://*.foo.com', 'http://b.foo.com/', true)
    assert_valid('http://*.foo.com', 'http://b.foo.com/', true)
    assert_valid('http://*.foo.com', 'http://b.foo.com', true)
    assert_valid('http://*.b.foo.com', 'http://b.foo.com', true)
    assert_valid('http://*.b.foo.com', 'http://x.b.foo.com', true)
    assert_valid('http://*.bar.co.uk', 'http://www.bar.co.uk', true)
    assert_valid('http://*.uoregon.edu', 'http://x.cs.uoregon.edu', true)

    assert_valid('http://*.cs.uoregon.edu', 'http://x.uoregon.edu', false)
    assert_valid('http://*.foo.com', 'http://bar.com', false)
    assert_valid('http://*.foo.com', 'http://www.bar.com', false)
    assert_valid('http://*.bar.co.uk', 'http://xxx.co.uk', false)

    # path validity
    assert_valid('http://x.com/abc', 'http://x.com/', false)
    assert_valid('http://x.com/abc', 'http://x.com/a', false)
    assert_valid('http://*.x.com/abc', 'http://foo.x.com/abc', true)
    assert_valid('http://*.x.com/abc', 'http://foo.x.com', false)
    assert_valid('http://*.x.com', 'http://foo.x.com/gallery', true)
    assert_valid('http://foo.x.com', 'http://foo.x.com/gallery', true)
    assert_valid('http://foo.x.com/gallery', 'http://foo.x.com/gallery/xxx', true)
    assert_valid('http://localhost:8081/x?action=openid',
                'http://localhost:8081/x?action=openid', true)
    assert_valid('http://*.x.com/gallery', 'http://foo.x.com/gallery', true)

    assert_valid('http://localhost:8082/?action=openid',
                'http://localhost:8082/?action=openid', true)
    assert_valid('http://goathack.livejournal.org:8020/',
                'http://goathack.livejournal.org:8020/openid/login.bml', true)

  end

end
