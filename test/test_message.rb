# last synced with Python openid.test.test_message on 6/29/2007.

require 'test/unit'
require 'openid/message'
require 'openid/assert'

include OpenID

# Tests a standard set of behaviors of Message.get_arg with variations on
# handling defaults.
def get_arg_tests(ns, key, expected=nil)
  assert_equal(expected, @m.get_arg(ns, key))

  if expected.nil?
    assert_equal(@m.get_arg(ns, key, :a_default), :a_default)
    assert_raise(IndexError) { @m.get_arg(ns, key, :no_default) }
  else
    assert_equal(@m.get_arg(ns, key, :a_default), expected)
    assert_equal(@m.get_arg(ns, key, :no_default), expected)
  end
end



class EmptyMessageTestCase < Test::Unit::TestCase
  
  def setup
    @m = OpenID::Message.new
  end

  def test_to_post_args
    assert_equal({}, @m.to_post_args)
  end

  def test_to_args
    assert_equal({}, @m.to_args)
  end

  def test_to_kvform
    assert_equal('', @m.to_kvform)
  end

  def test_to_url_encoded
    assert_equal('', @m.to_url_encoded)
  end

  def test_to_url
    base_url = 'http://base.url/'
    assert_equal(base_url, @m.to_url(base_url))
  end

  def test_get_openid
    assert_equal(nil, @m.get_openid_namespace)
  end

  def test_get_key_openid
    assert_raise(OpenID::UndefinedOpenIDNamespace) {
      @m.get_key(OpenID::OPENID_NS, nil)
    }
  end

  def test_get_key_bare
    assert_equal('foo', @m.get_key(OpenID::BARE_NS, 'foo'))
  end

  def test_get_key_ns1
    assert_equal(nil, @m.get_key(OpenID::OPENID1_NS, 'foo'))
  end

  def test_get_key_ns2
    assert_equal(nil, @m.get_key(OpenID::OPENID2_NS, 'foo'))
  end

  def test_get_key_ns3
    assert_equal(nil, @m.get_key('urn:something-special', 'foo'))
  end

  def test_has_key
    assert_raise(OpenID::UndefinedOpenIDNamespace) {
      @m.has_key?(OpenID::OPENID_NS, 'foo')
    }
  end

  def test_has_key_bare
    assert_equal(false, @m.has_key?(OpenID::BARE_NS, 'foo'))
  end

  def test_has_key_ns1
    assert_equal(false, @m.has_key?(OpenID::OPENID1_NS, 'foo'))
  end

  def test_has_key_ns2
    assert_equal(false, @m.has_key?(OpenID::OPENID2_NS, 'foo'))
  end

  def test_has_key_ns3
    assert_equal(false, @m.has_key?('urn:xxx', 'foo'))
  end

  def test_get_arg
    assert_raise(OpenID::UndefinedOpenIDNamespace) {
      @m.get_args(OpenID::OPENID_NS)
    }
  end

  def test_get_arg_bare
    get_arg_tests(ns=OpenID::BARE_NS, key='foo')
  end

  def test_get_arg_ns1
    get_arg_tests(ns=OpenID::OPENID1_NS, key='foo')
  end

  def test_get_arg_ns2
    get_arg_tests(ns=OpenID::OPENID2_NS, key='foo')
  end

  def test_get_arg_ns3
    get_arg_tests(ns='urn:nothing-significant', key='foo')
  end

  def test_get_args
    assert_raise(OpenID::UndefinedOpenIDNamespace) {
      @m.get_args(OpenID::OPENID_NS)
    }
  end

  def test_get_args_bare
    assert_equal({}, @m.get_args(OpenID::BARE_NS))
  end

  def test_get_args_ns1
    assert_equal({}, @m.get_args(OpenID::OPENID1_NS))
  end

  def test_get_args_ns2
    assert_equal({}, @m.get_args(OpenID::OPENID2_NS))
  end

  def test_get_args_ns3
    assert_equal({}, @m.get_args('urn:xxx'))
  end

  def test_update_args
    assert_raise(OpenID::UndefinedOpenIDNamespace) {
      @m.update_args(OpenID::OPENID_NS, {'does not'=>'matter'})
    }
  end

  def _test_update_args_ns(ns)
    updates = {
      'camper van beethoven' => 'david l',
      'magnolia electric, co' => 'jason m'
    }
    assert_equal({}, @m.get_args(ns))
    @m.update_args(ns, updates)
    assert_equal(updates, @m.get_args(ns))
  end

  def test_update_args_bare
    _test_update_args_ns(OpenID::BARE_NS)
  end
  def test_update_args_ns1
    _test_update_args_ns(OpenID::OPENID1_NS)
  end
  def test_update_args_ns2
    _test_update_args_ns(OpenID::OPENID2_NS)
  end
  def test_update_args_ns3
    _test_update_args_ns('urn:xxx')
  end

  def test_set_arg
    assert_raise(OpenID::UndefinedOpenIDNamespace) {
      @m.set_arg(OpenID::OPENID_NS,'does not','matter')
    }
  end

  def _test_set_arg_ns(ns)
    key = 'Camper Van Beethoven'
    value = 'David Lowery'
    assert_equal(nil, @m.get_arg(ns, key))
    @m.set_arg(ns, key, value)
    assert_equal(value, @m.get_arg(ns, key))
  end

  def test_set_arg_bare
    _test_set_arg_ns(OpenID::BARE_NS)
  end
  def test_set_arg_ns1
    _test_set_arg_ns(OpenID::OPENID1_NS)
  end
  def test_set_arg_ns2
    _test_set_arg_ns(OpenID::OPENID2_NS)
  end
  def test_set_arg_ns3
    _test_set_arg_ns('urn:xxx')
  end

  def test_del_arg
    assert_raise(OpenID::UndefinedOpenIDNamespace) {
      @m.set_arg(OpenID::OPENID_NS, 'does not', 'matter')
    }
  end

  def _test_del_arg_ns(ns)
    key = 'Fleeting Joys'
    assert_equal(nil, @m.del_arg(ns, key))
  end

  def test_del_arg_bare
    _test_del_arg_ns(OpenID::BARE_NS)
  end
  def test_del_arg_ns1
    _test_del_arg_ns(OpenID::OPENID1_NS)
  end
  def test_del_arg_ns2
    _test_del_arg_ns(OpenID::OPENID2_NS)
  end
  def test_del_arg_ns3
    _test_del_arg_ns('urn:xxx')
  end

  def test_isOpenID1
    assert_equal(false, @m.is_openid1)
  end

  def test_isOpenID2
    assert_equal(false, @m.is_openid2)
  end
end

class OpenID1MessageTest < Test::Unit::TestCase
  
  def setup
    @m = OpenID::Message.from_post_args({'openid.mode' => 'error',
                                        'openid.error' => 'unit test'})
  end
  
  def test_to_post_args
    assert_equal({'openid.mode' => 'error',
                   'openid.error' => 'unit test'},
                 @m.to_post_args)
  end

  def test_to_args
    assert_equal({'mode' => 'error',
                   'error' => 'unit test'},
                 @m.to_args)
  end

  def test_to_kvform
    assert_equal("error:unit test\nmode:error\n",
                 @m.to_kvform)
  end

  def test_to_url_encoded
    assert_equal('openid.error=unit+test&openid.mode=error',
                 @m.to_url_encoded)
  end
  
  def test_to_url
    base_url = 'http://base.url/'
    actual = @m.to_url(base_url)
    actual_base = actual[0...base_url.length]
    assert_equal(base_url, actual_base)
    assert_equal('?', actual[base_url.length].chr)
    query = actual[base_url.length+1..-1]
    assert_equal({'openid.mode'=>['error'],'openid.error'=>['unit test']},
                 CGI.parse(query))
  end

  def test_get_openid
    assert_equal(OpenID::OPENID1_NS, @m.get_openid_namespace)
  end

  def test_get_key_openid
    assert_equal('openid.mode', @m.get_key(OpenID::OPENID_NS, 'mode'))
  end

  def test_get_key_bare
    assert_equal('mode', @m.get_key(OpenID::BARE_NS, 'mode'))
  end

  def test_get_key_ns1
    assert_equal('openid.mode', @m.get_key(OpenID::OPENID1_NS, 'mode'))
  end

  def test_get_key_ns2
    assert_equal(nil, @m.get_key(OpenID::OPENID2_NS, 'mode'))
  end

  def test_get_key_ns2
    assert_equal(nil, @m.get_key(OpenID::OPENID2_NS, 'mode'))
  end

  def test_get_key_ns3
    assert_equal(nil, @m.get_key('urn:xxx', 'mode'))
  end

  def test_has_key
    assert_equal(true, @m.has_key?(OpenID::OPENID_NS, 'mode'))
  end
  def test_has_key_bare
    assert_equal(false, @m.has_key?(OpenID::BARE_NS, 'mode'))
  end
  def test_has_key_ns1
    assert_equal(true, @m.has_key?(OpenID::OPENID1_NS, 'mode'))
  end
  def test_has_key_ns2
    assert_equal(false, @m.has_key?(OpenID::OPENID2_NS, 'mode'))
  end
  def test_has_key_ns3
    assert_equal(false, @m.has_key?('urn:xxx', 'mode'))
  end

  def test_get_arg
    assert_equal('error', @m.get_arg(OpenID::OPENID_NS, 'mode'))
  end

  def test_get_arg_bare
    get_arg_tests(ns=OpenID::BARE_NS, key='mode')
  end

  def test_get_arg_ns
    get_arg_tests(ns=OpenID::OPENID_NS, key='mode', expected='error')
  end

  def test_get_arg_ns1
    get_arg_tests(ns=OpenID::OPENID1_NS, key='mode', expected='error')
  end

  def test_get_arg_ns2
    get_arg_tests(ns=OpenID::OPENID2_NS, key='mode')
  end

  def test_get_arg_ns3
    get_arg_tests(ns='urn:nothing-significant', key='mode')
  end

  def test_get_args
    assert_equal({'mode'=>'error','error'=>'unit test'},
                 @m.get_args(OpenID::OPENID_NS))
  end
  def test_get_args_bare
    assert_equal({}, @m.get_args(OpenID::BARE_NS))
  end
  def test_get_args_ns1
    assert_equal({'mode'=>'error','error'=>'unit test'},
                 @m.get_args(OpenID::OPENID1_NS))
  end
  def test_get_args_ns2
    assert_equal({}, @m.get_args(OpenID::OPENID2_NS))
  end
  def test_get_args_ns3
    assert_equal({}, @m.get_args('urn:xxx'))
  end

  def _test_update_args_ns(ns, before=nil)
    if before.nil?
      before = {}
    end
    update_args = {
      'Camper van Beethoven'=>'David Lowery',
      'Magnolia Electric Co.'=>'Jason Molina'
    }
    assert_equal(before, @m.get_args(ns))
    @m.update_args(ns, update_args)
    after = before.dup
    after.update(update_args)
    assert_equal(after, @m.get_args(ns))
  end

  def test_update_args
    _test_update_args_ns(OpenID::OPENID_NS, {'mode'=>'error','error'=>'unit test'})
  end
  def test_update_args_bare
    _test_update_args_ns(OpenID::BARE_NS)
  end
  def test_update_args_ns1
    _test_update_args_ns(OpenID::OPENID1_NS, {'mode'=>'error','error'=>'unit test'})
  end
  def test_update_args_ns2
    _test_update_args_ns(OpenID::OPENID2_NS)
  end
  def test_update_args_ns3
    _test_update_args_ns('urn:xxx')
  end

  def _test_set_arg_ns(ns)
    key = 'awesometown'
    value = 'funny'
    assert_equal(nil, @m.get_arg(ns,key))
    @m.set_arg(ns, key, value)
    assert_equal(value, @m.get_arg(ns,key))
  end

  def test_set_arg; _test_set_arg_ns(OpenID::OPENID_NS); end
  def test_set_arg_bare; _test_set_arg_ns(OpenID::BARE_NS); end
  def test_set_arg_ns1; _test_set_arg_ns(OpenID::OPENID1_NS); end
  def test_set_arg_ns2; _test_set_arg_ns(OpenID::OPENID2_NS); end
  def test_set_arg_ns3; _test_set_arg_ns('urn:xxx'); end

  def _test_del_arg_ns(ns)
    key = 'marry an'
    value = 'ice cream sandwich'
    @m.set_arg(ns, key, value)
    assert_equal(value, @m.get_arg(ns,key))
    @m.del_arg(ns,key)
    assert_equal(nil, @m.get_arg(ns,key))
  end

  def test_del_arg; _test_del_arg_ns(OpenID::OPENID_NS); end
  def test_del_arg_bare; _test_del_arg_ns(OpenID::BARE_NS); end
  def test_del_arg_ns1; _test_del_arg_ns(OpenID::OPENID1_NS); end
  def test_del_arg_ns2; _test_del_arg_ns(OpenID::OPENID2_NS); end
  def test_del_arg_ns3; _test_del_arg_ns('urn:yyy'); end

  def test_isOpenID1
    assert_equal(true, @m.is_openid1)
  end

  def test_isOpenID2
    assert_equal(false, @m.is_openid2)
  end
end

class OpenID1ExplicitMessageTest < OpenID1MessageTest
  # XXX - check to make sure the test suite will get built the way this
  # expects.
  def setup
    @m = OpenID::Message.from_post_args({'openid.mode'=>'error',
                                        'openid.error'=>'unit test',
                                        'openid.ns'=>OpenID::OPENID1_NS})
  end
end

class OpenID2MessageTest < Test::Unit::TestCase

  def setup
    @m = Message.from_post_args({'openid.mode'=>'error',
                                        'openid.error'=>'unit test',
                                        'openid.ns'=>OpenID::OPENID2_NS})
    @m.set_arg(BARE_NS, 'xey', 'value')
  end

  def test_to_post_args
    assert_equal({'openid.mode' => 'error',
                   'openid.error' => 'unit test',
                   'openid.ns' => OPENID2_NS,
                   'xey' => 'value',
                 }, @m.to_post_args)
  end

  def test_to_args
    @m.del_arg(BARE_NS, 'xey')
    assert_equal({'mode' => 'error',
                 'error' => 'unit test',
                 'ns' => OPENID2_NS},
                 @m.to_args)
  end

  def test_to_kvform
    @m.del_arg(BARE_NS, 'xey')
    assert_equal("error:unit test\nmode:error\nns:#{OPENID2_NS}\n",
                 @m.to_kvform)
  end

  def _test_urlencoded(s)
    expected_list = ["openid.error=unit+test",
                     "openid.mode=error",
                     "openid.ns=#{CGI.escape(OPENID2_NS)}",
                     "xey=value"]
    # Hard to do this with string comparison since the mapping doesn't
    # preserve order.
    encoded_list = s.split('&')
    encoded_list.sort!
    assert_equal(expected_list, encoded_list)
  end

  def test_to_urlencoded
    _test_urlencoded(@m.to_url_encoded)
  end

  def test_to_url
    base_url = 'http://base.url/'
    actual = @m.to_url(base_url)
    actual_base = actual[0...base_url.length]
    assert_equal(base_url, actual_base)
    assert_equal('?', actual[base_url.length].chr)
    query = actual[base_url.length+1..-1]
    _test_urlencoded(query)
  end

  def test_get_openid
    assert_equal(OPENID2_NS, @m.get_openid_namespace)
  end

  def test_get_key_openid
    assert_equal('openid.mode', @m.get_key(OPENID2_NS, 'mode'))
  end

  def test_get_key_bare
    assert_equal('mode', @m.get_key(BARE_NS, 'mode'))
  end

  def test_get_key_ns1
    assert_equal(nil, @m.get_key(OPENID1_NS, 'mode'))
  end

  def test_get_key_ns2
    assert_equal('openid.mode', @m.get_key(OPENID2_NS, 'mode'))
  end

  def test_get_key_ns3
    assert_equal(nil, @m.get_key('urn:xxx', 'mode'))
  end

  def test_has_key_openid
    assert_equal(true, @m.has_key?(OPENID_NS,'mode'))
  end

  def test_has_key_bare
    assert_equal(false, @m.has_key?(BARE_NS,'mode'))
  end

  def test_has_key_ns1
    assert_equal(false, @m.has_key?(OPENID1_NS,'mode'))
  end

  def test_has_key_ns2
    assert_equal(true, @m.has_key?(OPENID2_NS,'mode'))
  end

  def test_has_key_ns3
    assert_equal(false, @m.has_key?('urn:xxx','mode'))
  end

  # XXX - getArgTest
  def test_get_arg_openid
    assert_equal('error', @m.get_arg(OPENID_NS,'mode'))
  end

  def test_get_arg_bare
    assert_equal(nil, @m.get_arg(BARE_NS,'mode'))
  end

  def test_get_arg_ns1
    assert_equal(nil, @m.get_arg(OPENID1_NS,'mode'))
  end

  def test_get_arg_ns2
    assert_equal('error', @m.get_arg(OPENID2_NS,'mode'))
  end

  def test_get_arg_ns3
    assert_equal(nil, @m.get_arg('urn:bananastand','mode'))
  end

  def test_get_args_openid
    assert_equal({'mode'=>'error','error'=>'unit test'},
                 @m.get_args(OPENID_NS))
  end

  def test_get_args_bare
    assert_equal({'xey'=>'value'},
                 @m.get_args(BARE_NS))
  end

  def test_get_args_ns1
    assert_equal({},
                 @m.get_args(OPENID1_NS))
  end

  def test_get_args_ns2
    assert_equal({'mode'=>'error','error'=>'unit test'},
                 @m.get_args(OPENID2_NS))
  end

  def test_get_args_ns3
    assert_equal({},
                 @m.get_args('urn:loose seal'))
  end

  def _test_update_args_ns(ns, before=nil)
    before = {} unless before
    update_args = {'aa'=>'bb','cc'=>'dd'}

    assert_equal(before, @m.get_args(ns))
    @m.update_args(ns, update_args)
    after = before.dup
    after.update(update_args)
    assert_equal(after, @m.get_args(ns))
  end

  def test_update_args_openid
    _test_update_args_ns(OPENID_NS, {'mode'=>'error','error'=>'unit test'})
  end

  def test_update_args_bare
    _test_update_args_ns(BARE_NS, {'xey'=>'value'})
  end

  def test_update_args_ns1
    _test_update_args_ns(OPENID1_NS)
  end
  
  def test_update_args_ns2
    _test_update_args_ns(OPENID2_NS, {'mode'=>'error','error'=>'unit test'})
  end

  def test_update_args_ns3
    _test_update_args_ns('urn:sven')
  end

  def _test_set_arg_ns(ns)
    key = "logan's"
    value = "run"
    assert_equal(nil, @m.get_arg(ns,key))
    @m.set_arg(ns, key, value)
    assert_equal(value, @m.get_arg(ns,key))
  end

  def test_set_arg_openid; _test_set_arg_ns(OPENID_NS); end
  def test_set_arg_bare; _test_set_arg_ns(BARE_NS); end
  def test_set_arg_ns1; _test_set_arg_ns(OPENID1_NS); end
  def test_set_arg_ns2; _test_set_arg_ns(OPENID2_NS); end
  def test_set_arg_ns3; _test_set_arg_ns('urn:g'); end

  def test_bad_alias
    # Make sure dotted aliases and OpenID protocol fields are not allowed
    # as namespace aliases.

    fields = OPENID_PROTOCOL_FIELDS + ['dotted.alias']

    fields.each { |f|
      args = {"openid.ns.#{f}" => "blah#{f}",
        "openid.#{f}.foo" => "test#{f}"}

      # .fromPostArgs covers .fromPostArgs, .fromOpenIDArgs,
      # ._fromOpenIDArgs, and .fromOpenIDArgs (since it calls
      # .fromPostArgs).
      assert_raise(AssertionError) {
        Message.from_post_args(args)
      }
    }
  end

  def _test_del_arg_ns(ns)
    key = 'no'
    value = 'socks'
    assert_equal(nil, @m.get_arg(ns, key))
    @m.set_arg(ns, key, value)
    assert_equal(value, @m.get_arg(ns, key))
    @m.del_arg(ns, key)
    assert_equal(nil, @m.get_arg(ns, key))
  end

  def test_del_arg_openid; _test_del_arg_ns(OPENID_NS); end
  def test_del_arg_bare; _test_del_arg_ns(BARE_NS); end
  def test_del_arg_ns1; _test_del_arg_ns(OPENID1_NS); end
  def test_del_arg_ns2; _test_del_arg_ns(OPENID2_NS); end
  def test_del_arg_ns3; _test_del_arg_ns('urn:tofu'); end

  def test_overwrite_extension_arg
    ns = 'urn:unittest_extension'
    key = 'mykey'
    value_1 = 'value_1'
    value_2 = 'value_2'

    @m.set_arg(ns, key, value_1)
    assert_equal(value_1, @m.get_arg(ns, key))
    @m.set_arg(ns, key, value_2)
    assert_equal(value_2, @m.get_arg(ns, key))
  end

  def test_isOpenID1
    assert_equal(false, @m.is_openid1)
  end

  def test_isOpenID2
    assert_equal(true, @m.is_openid2)
  end
end

# TODO
# class MessageTest < Test::Unit::TestCase
#   def test_to_form_markup
#     flunk 'port from test_message.py'
#   end

#   def test_override_method
#     flunk 'port from test_message.py'
#   end

#   def test_override_required
#     flunk 'port from test_message.py'
#   end
# end

class NamespaceMapTestCase < Test::Unit::TestCase
  
  def test_onealias
    nsm = OpenID::NamespaceMap.new
    uri = 'http://example.com/foo'
    _alias = 'foo'
    nsm.add_alias(uri, _alias)
    assert_equal(uri, nsm.get_namespace_uri(_alias))
    assert_equal(_alias, nsm.get_alias(uri))
  end

  
  def test_iteration
    nsm = NamespaceMap.new
    uripat = "http://example.com/foo%i"
    nsm.add(uripat % 0)

    (1..23).each { |i|
      assert_equal(false, nsm.contains?(uripat % i))
      assert_equal(false, nsm.defined?(uripat % i))
      nsm.add(uripat % i)
    }
    nsm.each { |uri, _alias|
      assert_equal(uri[22..-1], _alias[3..-1])
    }

    # TODO:
    #flunk 'exercise iterAliases?'
    #flunk 'exercise iterNamespaceURIs?'
  end

end