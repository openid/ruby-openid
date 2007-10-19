require 'test/unit'
require 'yadis/parsehtml'

class YadisHTMLParseTestCase < Test::Unit::TestCase

  def check(x, html)
    result = html_yadis_location(html)
    assert_equal(x, result)
  end

  def test_valid
    check('foo', '<html><head><meta http-equiv="X-YADIS-LOCATION" content="foo"/></head></html>')
    
    check('foo', '<html><head><meta http-equiv="X-YADIS-LOCATION" content="foo"/></head></html>')
    check('foo', '<html><head><meta http-equiv="X-YADIS-LOCATION" content="foo"/></head></html>')
    check('foo', '<html><head><meta HTTP-EQUIV="X-YADIS-LOCATION" CONTENT="foo"/></head></html>')
    check('foo', '<html><head><meta HTTP-EQUIV="X-YADIS-Location" CONTENT="foo"/></head></html>')
    check('http://brian.myopenid.com/xrds', File.open('data/index.html').read)
    check('http://brian.myopenid.com/xrds', File.open('data/index_xrds.html').read)
    check('http://brian.myopenid.com/xrds', File.open('data/index_yadis.html').read)
  end

  def test_fail
    check(nil, '')
    check(nil, nil)
    check(nil, 5)
    check(nil, '<html></html>')

    # no content attr
    check(nil, '<html><head><meta http-equiv="x-yadis-location" /><meta http-equiv="X-YADIS-LOCATION" content="foo"/></head></html>')

    # not in head
    check(nil, '<html><meta http-equiv="X-YADIS-LOCATION" content="foo"/></html>')
    check(nil, '<html><body><meta http-equiv="X-YADIS-LOCATION" content="foo"/></html>')
  end

end
