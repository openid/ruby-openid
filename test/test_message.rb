# last synced with Python openid.test.test_message on 6/29/2007.

require 'test/unit'
require 'openid/message'

require 'rexml/document'

include OpenID

# Tests a standard set of behaviors of Message.get_arg with variations on
# handling defaults.
def get_arg_tests(ns, key, expected=nil)
  assert_equal(expected, @m.get_arg(ns, key))

  if expected.nil?
    assert_equal(@m.get_arg(ns, key, :a_default), :a_default)
    assert_raise(IndexError) { @m.get_arg(ns, key, NO_DEFAULT) }
  else
    assert_equal(@m.get_arg(ns, key, :a_default), expected)
    assert_equal(@m.get_arg(ns, key, NO_DEFAULT), expected)
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

  def test_set_openid_namespace
    assert_raise(ArgumentError) {
      @m.set_openid_namespace('http://invalid/')
    }
  end
end

class OpenID1MessageTest < Test::Unit::TestCase

  def setup
    @m = OpenID::Message.from_post_args({'openid.mode' => 'error',
                                          'openid.error' => 'unit test'})
  end

  def test_has_openid_ns
    assert_equal(OpenID::OPENID1_NS, @m.get_openid_namespace)
    assert_equal(OpenID::OPENID1_NS,
                 @m.namespaces.get_namespace_uri(OpenID::NULL_NAMESPACE))
  end

  def test_get_aliased_arg
    assert_equal('error', @m.get_aliased_arg('mode'))
  end

  def test_get_aliased_arg_ns
    assert_equal(OpenID::OPENID1_NS, @m.get_aliased_arg('ns'))
  end

  def test_get_aliased_arg_with_ns
    @m = OpenID::Message.from_post_args(
        {'openid.mode' => 'error',
         'openid.error' => 'unit test',
         'openid.ns.invalid' => 'http://invalid/',
         'openid.invalid.stuff' => 'things',
        })
    assert_equal('http://invalid/', @m.get_aliased_arg('ns.invalid'))
    assert_equal('things', @m.get_aliased_arg('invalid.stuff'))
  end

  def test_get_aliased_arg_with_ns_default
    @m = OpenID::Message.from_post_args({})
    assert_equal('monkeys!', @m.get_aliased_arg('ns.invalid',
                                                default="monkeys!"))
  end

  def test_to_post_args
    assert_equal({'openid.mode' => 'error',
                   'openid.error' => 'unit test'},
                 @m.to_post_args)
  end

  def test_to_post_args_ns
    invalid_ns = 'http://invalid/'
    @m.namespaces.add_alias(invalid_ns, 'foos')
    @m.set_arg(invalid_ns, 'ball', 'awesome')
    @m.set_arg(OpenID::BARE_NS, 'xey', 'value')
    assert_equal({'openid.mode' => 'error',
                   'openid.error' => 'unit test',
                   'openid.foos.ball' => 'awesome',
                   'xey' => 'value',
                 }, @m.to_post_args)
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

  def test_equal
    assert(Message.new.eql?(Message.new))
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

  def test_to_args_fails
    assert_raises(ArgumentError) {
      @m.to_args
    }
  end

  def test_fix_ns_non_string
    assert_raises(ArgumentError) {
      @m.has_key?(:non_string_namespace, "key")
    }
  end

  def test_copy
    n = @m.copy
    assert(@m.eql?(n))
  end

  def test_to_post_args
    assert_equal({'openid.mode' => 'error',
                   'openid.error' => 'unit test',
                   'openid.ns' => OPENID2_NS,
                   'xey' => 'value',
                 }, @m.to_post_args)
  end

  def test_to_post_args_ns
    invalid_ns = 'http://invalid/'
    @m.namespaces.add_alias(invalid_ns, 'foos')
    @m.set_arg(invalid_ns, 'ball', 'awesome')
    assert_equal({'openid.mode' => 'error',
                   'openid.error' => 'unit test',
                   'openid.ns' => OPENID2_NS,
                   'openid.ns.foos' => invalid_ns,
                   'openid.foos.ball' => 'awesome',
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

  def test_from_post_args
    msg = Message.from_post_args({'foos' => 'ball'})
    assert_equal('ball', msg.get_arg(OpenID::BARE_NS, 'foos'))
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

class MessageTest < Test::Unit::TestCase
  def setup
    @postargs = {
      'openid.ns' => OPENID2_NS,
      'openid.mode' => 'checkid_setup',
      'openid.identity' => 'http://bogus.example.invalid:port/',
      'openid.assoc_handle' => 'FLUB',
      'openid.return_to' => 'Neverland',
    }

    @action_url = 'scheme://host:port/path?query'

    @form_tag_attrs = {
      'company' => 'janrain',
      'class' => 'fancyCSS',
    }

    @submit_text = 'GO!'

    ### Expected data regardless of input

    @required_form_attrs = {
      'accept-charset' => 'UTF-8',
      'enctype' => 'application/x-www-form-urlencoded',
      'method' => 'post',
    }
  end

  def _checkForm(html, message_, action_url,
                 form_tag_attrs, submit_text)
    @xml = REXML::Document.new(html)

    # Get root element
    form = @xml.root

    # Check required form attributes
    @required_form_attrs.each { |k, v|
      assert(form.attributes[k] == v,
             "Expected '#{v}' for required form attribute '#{k}', got '#{form.attributes[k]}'")
    }

    # Check extra form attributes
    @form_tag_attrs.each { |k, v|
      # Skip attributes that already passed the required attribute
      # check, since they should be ignored by the form generation
      # code.
      if @required_form_attrs.include?(k)
        continue
      end

      assert(form.attributes[k] == v,
             "Form attribute '#{k}' should be '#{v}', found '#{form.attributes[k]}'")

      # Check hidden fields against post args
      hiddens = []
      form.each { |e|
        if (e.is_a?(REXML::Element)) and
            (e.name.upcase() == 'INPUT') and
            (e.attributes['type'].upcase() == 'HIDDEN')
          # For each post arg, make sure there is a hidden with that
          # value.  Make sure there are no other hiddens.
          hiddens += [e]
        end
      }

      message_.to_post_args().each { |name, value|
        success = false

        hiddens.each { |e|
          if e.attributes['name'] == name
            assert(e.attributes['value'] == value,
                   "Expected value of hidden input '#{e.attributes['name']}' " +
                   "to be '#{value}', got '#{e.attributes['value']}'")
            success = true
            break
          end
        }

        if !success
          flunk "Post arg '#{name}' not found in form"
        end
      }

      hiddens.each { |e|
        assert(message_.to_post_args().keys().include?(e.attributes['name']),
               "Form element for '#{e.attributes['name']}' not in " +
               "original message")
      }

      # Check action URL
      assert(form.attributes['action'] == action_url,
             "Expected form 'action' to be '#{action_url}', got '#{form.attributes['action']}'")

      # Check submit text
      submits = []
      form.each { |e|
        if (e.is_a?(REXML::Element)) and
            (e.name.upcase() == 'INPUT') and
            e.attributes['type'].upcase() == 'SUBMIT'
          submits += [e]
        end
      }

      assert(submits.length == 1,
             "Expected only one 'input' with type = 'submit', got #{submits.length}")

      assert(submits[0].attributes['value'] == submit_text,
             "Expected submit value to be '#{submit_text}', " +
             "got '#{submits[0].attributes['value']}'")
    }

  end

  def test_toFormMarkup
    m = Message.from_post_args(@postargs)
    html = m.to_form_markup(@action_url, @form_tag_attrs,
                            @submit_text)
    _checkForm(html, m, @action_url,
               @form_tag_attrs, @submit_text)
  end

  def test_overrideMethod
    # Be sure that caller cannot change form method to GET.
    m = Message.from_post_args(@postargs)

    tag_attrs = @form_tag_attrs.clone
    tag_attrs['method'] = 'GET'

    html = m.to_form_markup(@action_url, @form_tag_attrs,
                            @submit_text)
    _checkForm(html, m, @action_url,
               @form_tag_attrs, @submit_text)
  end

  def test_overrideRequired
    # Be sure that caller CANNOT change the form charset for
    # encoding type.
    m = Message.from_post_args(@postargs)

    tag_attrs = @form_tag_attrs.clone
    tag_attrs['accept-charset'] = 'UCS4'
    tag_attrs['enctype'] = 'invalid/x-broken'

    html = m.to_form_markup(@action_url, tag_attrs,
                            @submit_text)
    _checkForm(html, m, @action_url,
               tag_attrs, @submit_text)
  end
end

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

    nsm = NamespaceMap.new
    alias_ = 'bogus'
    uri = 'urn:bogus'

    nsm.add_alias(uri, alias_)

    assert_equal(nsm.iter_aliases(), [alias_])
    assert_equal(nsm.iter_namespace_uris(), [uri])
  end

  def test_register_default_alias
    invalid_ns = 'http://invalid/'
    alias_ = 'invalid'
    OpenID::register_namespace_alias(invalid_ns, alias_)
    # Doing it again doesn't raise an exception
    OpenID::register_namespace_alias(invalid_ns, alias_)

    # Once it's registered, you can't register it again
    assert_raises(NamespaceAliasRegistrationError) {
      OpenID::register_namespace_alias(invalid_ns, 'another_alias')
    }

    # Once it's registered, you can't register another URL with that alias
    assert_raises(NamespaceAliasRegistrationError) {
      OpenID::register_namespace_alias('http://janrain.com/', alias_)
    }

    # It gets used automatically by the Message class:
    msg = OpenID::Message.from_openid_args({'invalid.stuff' => 'things'})
    assert_equal(alias_, msg.namespaces.get_alias(invalid_ns))
    assert_equal(invalid_ns, msg.namespaces.get_namespace_uri(alias_))
  end
end
