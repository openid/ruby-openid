
require 'openid/server/server'
require 'openid/cryptutil'
require 'openid/association'
require 'openid/util'
require 'openid/message'
require 'openid/store/memstore'

require 'test/unit'
require 'uri'

# In general, if you edit or add tests here, try to move in the
# direction of testing smaller units.  For testing the external
# interfaces, we'll be developing an implementation-agnostic testing
# suite.

# for more, see /etc/ssh/moduli

include OpenID, OpenID::Server

ALT_MODULUS = 0xCAADDDEC1667FC68B5FA15D53C4E1532DD24561A1A2D47A12C01ABEA1E00731F6921AAC40742311FDF9E634BB7131BEE1AF240261554389A910425E044E88C8359B010F5AD2B80E29CB1A5B027B19D9E01A6F63A6F45E5D7ED2FF6A2A0085050A7D0CF307C3DB51D2490355907B4427C23A98DF1EB8ABEF2BA209BB7AFFE86A7
ALT_GEN = 5

class CatchLogs
  def setup
    @old_logger = Util.logger
    Util.logger = self.method('got_log_message')
    @messages = []
  end

  def got_log_message(message)
    @messages << message
  end

  def teardown
    Util.logger = @old_logger
  end
end

class TestProtocolError < Test::Unit::TestCase
  def test_browserWithReturnTo
    return_to = "http://rp.unittest/consumer"
    # will be a ProtocolError raised by Decode or
    # CheckIDRequest.answer
    args = Message.from_post_args({
            'openid.mode' => 'monkeydance',
            'openid.identity' => 'http://wagu.unittest/',
            'openid.return_to' => return_to,
                                  })
    e = ProtocolError.new(args, "plucky")
    assert(e.has_return_to)
    expected_args = {
            'openid.mode' => 'error',
            'openid.error' => 'plucky',
    }

    rt_base, result_args = e.encode_to_url.split('?', 2)
    result_args = Util.parse_query(result_args)
    assert_equal(result_args, expected_args)
  end

  def test_browserWithReturnTo_OpenID2_GET
    return_to = "http://rp.unittest/consumer"
    # will be a ProtocolError raised by Decode or
    # CheckIDRequest.answer
    args = Message.from_post_args({
            'openid.ns' => OPENID2_NS,
            'openid.mode' => 'monkeydance',
            'openid.identity' => 'http://wagu.unittest/',
            'openid.claimed_id' => 'http://wagu.unittest/',
            'openid.return_to' => return_to,
                                  })
    e = ProtocolError.new(args, "plucky")
    assert(e.has_return_to)
    expected_args = {
      'openid.ns' => OPENID2_NS,
      'openid.mode' => 'error',
      'openid.error' => 'plucky',
    }

    rt_base, result_args = e.encode_to_url.split('?', 2)
    result_args = Util.parse_query(result_args)
    assert_equal(result_args, expected_args)
  end

  def test_browserWithReturnTo_OpenID2_POST
    return_to = "http://rp.unittest/consumer" + ('x' * OPENID1_URL_LIMIT)
    # will be a ProtocolError raised by Decode or
    # CheckIDRequest.answer
    args = Message.from_post_args({
                                  'openid.ns' => OPENID2_NS,
                                  'openid.mode' => 'monkeydance',
                                  'openid.identity' => 'http://wagu.unittest/',
                                  'openid.claimed_id' => 'http://wagu.unittest/',
                                  'openid.return_to' => return_to,
                                })
    e = ProtocolError.new(args, "plucky")
    assert(e.has_return_to)
    expected_args = {
      'openid.ns' => OPENID2_NS,
      'openid.mode' => 'error',
      'openid.error' => 'plucky',
    }

    assert(e.which_encoding == ENCODE_HTML_FORM)
    assert(e.to_form_markup == e.to_message.to_form_markup(
                       args.get_arg(OPENID_NS, 'return_to')))
  end

  def test_browserWithReturnTo_OpenID1_exceeds_limit
    return_to = "http://rp.unittest/consumer" + ('x' * OPENID1_URL_LIMIT)
    # will be a ProtocolError raised by Decode or
    # CheckIDRequest.answer
    args = Message.from_post_args({
                                    'openid.mode' => 'monkeydance',
                                    'openid.identity' => 'http://wagu.unittest/',
                                    'openid.return_to' => return_to,
                                  })
    e = ProtocolError.new(args, "plucky")
    assert(e.has_return_to)
    expected_args = {
      'openid.mode' => 'error',
      'openid.error' => 'plucky',
    }

    assert(e.which_encoding == ENCODE_URL)

    rt_base, result_args = e.encode_to_url.split('?', 2)
    result_args = Util.parse_query(result_args)
    assert_equal(result_args, expected_args)
  end

  def test_noReturnTo
    # will be a ProtocolError raised by Decode or
    # CheckIDRequest.answer
    args = Message.from_post_args({
                                    'openid.mode' => 'zebradance',
                                    'openid.identity' => 'http://wagu.unittest/',
                                  })
    e = ProtocolError.new(args, "waffles")
    assert(!e.has_return_to)
    expected = "error:waffles\nmode:error\n"
    assert_equal(e.encode_to_kvform, expected)
  end
end

class TestDecode < Test::Unit::TestCase
  def setup
    @claimed_id = 'http://de.legating.de.coder.unittest/'
    @id_url = "http://decoder.am.unittest/"
    @rt_url = "http://rp.unittest/foobot/?qux=zam"
    @tr_url = "http://rp.unittest/"
    @assoc_handle = "{assoc}{handle}"
    @op_endpoint = 'http://endpoint.unittest/encode'
    @store = MemoryStore.new()
    @server = Server::Server.new(@store, @op_endpoint)
    @decode = Server::Decoder.new(@server).method('decode')
  end

  def test_none
    args = {}
    r = @decode.call(args)
    assert_equal(r, nil)
  end

  def test_irrelevant
    args = {
      'pony' => 'spotted',
      'sreg.mutant_power' => 'decaffinator',
    }
    assert_raise(ProtocolError) {
      @decode.call(args)
    }
  end

  def test_bad
    args = {
      'openid.mode' => 'twos-compliment',
      'openid.pants' => 'zippered',
    }
    assert_raise(ProtocolError) {
      @decode.call(args)
    }
  end

  def test_dictOfLists
    args = {
      'openid.mode' => ['checkid_setup'],
      'openid.identity' => @id_url,
      'openid.assoc_handle' => @assoc_handle,
      'openid.return_to' => @rt_url,
      'openid.trust_root' => @tr_url,
    }
    begin
      result = @decode.call(args)
    rescue ArgumentError => err
      assert(!err.to_s.index('values').nil?, err)
    else
      flunk("Expected ArgumentError, but got result #{result}")
    end
  end

  def test_checkidImmediate
    args = {
      'openid.mode' => 'checkid_immediate',
      'openid.identity' => @id_url,
      'openid.assoc_handle' => @assoc_handle,
      'openid.return_to' => @rt_url,
      'openid.trust_root' => @tr_url,
      # should be ignored
      'openid.some.extension' => 'junk',
    }
    r = @decode.call(args)
    assert(r.is_a?(CheckIDRequest))
    assert_equal(r.mode, "checkid_immediate")
    assert_equal(r.immediate, true)
    assert_equal(r.identity, @id_url)
    assert_equal(r.trust_root, @tr_url)
    assert_equal(r.return_to, @rt_url)
    assert_equal(r.assoc_handle, @assoc_handle)
  end

  def test_checkidSetup
    args = {
      'openid.mode' => 'checkid_setup',
      'openid.identity' => @id_url,
      'openid.assoc_handle' => @assoc_handle,
      'openid.return_to' => @rt_url,
      'openid.trust_root' => @tr_url,
    }
    r = @decode.call(args)
    assert(r.is_a?(CheckIDRequest))
    assert_equal(r.mode, "checkid_setup")
    assert_equal(r.immediate, false)
    assert_equal(r.identity, @id_url)
    assert_equal(r.trust_root, @tr_url)
    assert_equal(r.return_to, @rt_url)
  end

  def test_checkidSetupOpenID2
    args = {
      'openid.ns' => OPENID2_NS,
      'openid.mode' => 'checkid_setup',
      'openid.identity' => @id_url,
      'openid.claimed_id' => @claimed_id,
      'openid.assoc_handle' => @assoc_handle,
      'openid.return_to' => @rt_url,
      'openid.realm' => @tr_url,
    }
    r = @decode.call(args)
    assert(r.is_a?(CheckIDRequest))
    assert_equal(r.mode, "checkid_setup")
    assert_equal(r.immediate, false)
    assert_equal(r.identity, @id_url)
    assert_equal(r.claimed_id, @claimed_id)
    assert_equal(r.trust_root, @tr_url)
    assert_equal(r.return_to, @rt_url)
  end

  def test_checkidSetupNoClaimedIDOpenID2
    args = {
      'openid.ns' => OPENID2_NS,
      'openid.mode' => 'checkid_setup',
      'openid.identity' => @id_url,
      'openid.assoc_handle' => @assoc_handle,
      'openid.return_to' => @rt_url,
      'openid.realm' => @tr_url,
    }
    assert_raise(ProtocolError) {
      @decode.call(args)
    }
  end

  def test_checkidSetupNoIdentityOpenID2
    args = {
      'openid.ns' => OPENID2_NS,
      'openid.mode' => 'checkid_setup',
      'openid.assoc_handle' => @assoc_handle,
      'openid.return_to' => @rt_url,
      'openid.realm' => @tr_url,
    }
    r = @decode.call(args)
    assert(r.is_a?(CheckIDRequest))
    assert_equal(r.mode, "checkid_setup")
    assert_equal(r.immediate, false)
    assert_equal(r.identity, nil)
    assert_equal(r.trust_root, @tr_url)
    assert_equal(r.return_to, @rt_url)
  end

  def test_checkidSetupNoReturnOpenID1
    # Make sure an OpenID 1 request cannot be decoded if it lacks a
    # return_to.
    args = {
      'openid.mode' => 'checkid_setup',
      'openid.identity' => @id_url,
      'openid.assoc_handle' => @assoc_handle,
      'openid.trust_root' => @tr_url,
    }
    assert_raise(ProtocolError) {
      @decode.call(args)
    }
  end

  def test_checkidSetupNoReturnOpenID2
    # Make sure an OpenID 2 request with no return_to can be decoded,
    # and make sure a response to such a request raises
    # NoReturnToError.
    args = {
      'openid.ns' => OPENID2_NS,
      'openid.mode' => 'checkid_setup',
      'openid.identity' => @id_url,
      'openid.claimed_id' => @id_url,
      'openid.assoc_handle' => @assoc_handle,
      'openid.realm' => @tr_url,
    }

    req = @decode.call(args)
    assert(req.is_a?(CheckIDRequest))

    assert_raise(NoReturnToError) {
      req.answer(false)
    }

    assert_raise(NoReturnToError) {
      req.encode_to_url('bogus')
    }

    assert_raise(NoReturnToError) {
      req.get_cancel_url
    }
  end

  def test_checkidSetupRealmRequiredOpenID2
    # Make sure that an OpenID 2 request which lacks return_to cannot
    # be decoded if it lacks a realm.  Spec => This value
    # (openid.realm) MUST be sent if openid.return_to is omitted.
    args = {
      'openid.ns' => OPENID2_NS,
      'openid.mode' => 'checkid_setup',
      'openid.identity' => @id_url,
      'openid.assoc_handle' => @assoc_handle,
    }
    assert_raise(ProtocolError) {
      @decode.call(args)
    }
  end

  def test_checkidSetupBadReturn
    args = {
      'openid.mode' => 'checkid_setup',
      'openid.identity' => @id_url,
      'openid.assoc_handle' => @assoc_handle,
      'openid.return_to' => 'not a url',
    }
    begin
      result = @decode.call(args)
    rescue ProtocolError => err
      assert(err.openid_message)
    else
      flunk("Expected ProtocolError, instead returned with #{result}")
    end
  end

  def test_checkidSetupUntrustedReturn
    args = {
      'openid.mode' => 'checkid_setup',
      'openid.identity' => @id_url,
      'openid.assoc_handle' => @assoc_handle,
      'openid.return_to' => @rt_url,
      'openid.trust_root' => 'http://not-the-return-place.unittest/',
    }
    begin
      result = @decode.call(args)
    rescue UntrustedReturnURL => err
      assert(err.openid_message)
    else
      flunk("Expected UntrustedReturnURL, instead returned with #{result}")
    end
  end

  def test_checkAuth
    args = {
      'openid.mode' => 'check_authentication',
      'openid.assoc_handle' => '{dumb}{handle}',
      'openid.sig' => 'sigblob',
      'openid.signed' => 'identity,return_to,response_nonce,mode',
      'openid.identity' => 'signedval1',
      'openid.return_to' => 'signedval2',
      'openid.response_nonce' => 'signedval3',
      'openid.baz' => 'unsigned',
    }
    r = @decode.call(args)
    assert(r.is_a?(CheckAuthRequest))
    assert_equal(r.mode, 'check_authentication')
    assert_equal(r.sig, 'sigblob')
  end

  def test_checkAuthMissingSignature
    args = {
      'openid.mode' => 'check_authentication',
      'openid.assoc_handle' => '{dumb}{handle}',
      'openid.signed' => 'foo,bar,mode',
      'openid.foo' => 'signedval1',
      'openid.bar' => 'signedval2',
      'openid.baz' => 'unsigned',
    }
    assert_raise(ProtocolError) {
      @decode.call(args)
    }
  end

  def test_checkAuthAndInvalidate
    args = {
      'openid.mode' => 'check_authentication',
      'openid.assoc_handle' => '{dumb}{handle}',
      'openid.invalidate_handle' => '[[SMART_handle]]',
      'openid.sig' => 'sigblob',
      'openid.signed' => 'identity,return_to,response_nonce,mode',
      'openid.identity' => 'signedval1',
      'openid.return_to' => 'signedval2',
      'openid.response_nonce' => 'signedval3',
      'openid.baz' => 'unsigned',
    }
    r = @decode.call(args)
    assert(r.is_a?(CheckAuthRequest))
    assert_equal(r.invalidate_handle, '[[SMART_handle]]')
  end

  def test_associateDH
    args = {
      'openid.mode' => 'associate',
      'openid.session_type' => 'DH-SHA1',
      'openid.dh_consumer_public' => "Rzup9265tw==",
    }
    r = @decode.call(args)
    assert(r.is_a?(AssociateRequest))
    assert_equal(r.mode, "associate")
    assert_equal(r.session.session_type, "DH-SHA1")
    assert_equal(r.assoc_type, "HMAC-SHA1")
    assert(r.session.consumer_pubkey)
  end

  def test_associateDHMissingKey
    # Trying DH assoc w/o public key
    args = {
      'openid.mode' => 'associate',
      'openid.session_type' => 'DH-SHA1',
    }
    # Using DH-SHA1 without supplying dh_consumer_public is an error.
    assert_raise(ProtocolError) {
      @decode.call(args)
    }
  end

  def test_associateDHpubKeyNotB64
      args = {
      'openid.mode' => 'associate',
      'openid.session_type' => 'DH-SHA1',
      'openid.dh_consumer_public' => "donkeydonkeydonkey",
    }
    assert_raise(ProtocolError) {
      @decode.call(args)
    }
  end

  def test_associateDHModGen
    # test dh with non-default but valid values for dh_modulus and
    # dh_gen
    args = {
      'openid.mode' => 'associate',
      'openid.session_type' => 'DH-SHA1',
      'openid.dh_consumer_public' => "Rzup9265tw==",
      'openid.dh_modulus' => CryptUtil.num_to_base64(ALT_MODULUS),
      'openid.dh_gen' => CryptUtil.num_to_base64(ALT_GEN) ,
    }
    r = @decode.call(args)
    assert(r.is_a?(AssociateRequest))
    assert_equal(r.mode, "associate")
    assert_equal(r.session.session_type, "DH-SHA1")
    assert_equal(r.assoc_type, "HMAC-SHA1")
    assert_equal(r.session.dh.modulus, ALT_MODULUS)
    assert_equal(r.session.dh.generator, ALT_GEN)
    assert(r.session.consumer_pubkey)
  end

  def test_associateDHCorruptModGen
    # test dh with non-default but valid values for dh_modulus and
    # dh_gen
    args = {
      'openid.mode' => 'associate',
      'openid.session_type' => 'DH-SHA1',
      'openid.dh_consumer_public' => "Rzup9265tw==",
      'openid.dh_modulus' => 'pizza',
      'openid.dh_gen' => 'gnocchi',
    }
    assert_raise(ProtocolError) {
      @decode.call(args)
    }
  end

  def test_associateDHMissingModGen
    # test dh with non-default but valid values for dh_modulus and
    # dh_gen
    args = {
      'openid.mode' => 'associate',
      'openid.session_type' => 'DH-SHA1',
      'openid.dh_consumer_public' => "Rzup9265tw==",
      'openid.dh_modulus' => 'pizza',
    }
    assert_raise(ProtocolError) {
      @decode.call(args)
    }
  end

#     def test_associateDHInvalidModGen(self):
#         # test dh with properly encoded values that are not a valid
#         #   modulus/generator combination.
#         args = {
#             'openid.mode': 'associate',
#             'openid.session_type': 'DH-SHA1',
#             'openid.dh_consumer_public': "Rzup9265tw==",
#             'openid.dh_modulus': cryptutil.longToBase64(9),
#             'openid.dh_gen': cryptutil.longToBase64(27) ,
#             }
#         self.failUnlessRaises(server.ProtocolError, self.decode, args)
#     test_associateDHInvalidModGen.todo = "low-priority feature"

  def test_associateWeirdSession
    args = {
      'openid.mode' => 'associate',
      'openid.session_type' => 'FLCL6',
      'openid.dh_consumer_public' => "YQ==\n",
    }
    assert_raise(ProtocolError) {
      @decode.call(args)
    }
  end

  def test_associatePlain
    args = {
      'openid.mode' => 'associate',
    }
    r = @decode.call(args)
    assert(r.is_a?(AssociateRequest))
    assert_equal(r.mode, "associate")
    assert_equal(r.session.session_type, "no-encryption")
    assert_equal(r.assoc_type, "HMAC-SHA1")
  end

  def test_nomode
    args = {
      'openid.session_type' => 'DH-SHA1',
      'openid.dh_consumer_public' => "my public keeey",
    }
    assert_raise(ProtocolError) {
      @decode.call(args)
    }
  end
end

class TestEncode < Test::Unit::TestCase
  def setup
    @encoder = Encoder.new
    @encode = @encoder.method('encode')
    @op_endpoint = 'http://endpoint.unittest/encode'
    @store = MemoryStore.new
    @server = Server::Server.new(@store, @op_endpoint)
  end

  def test_id_res_OpenID2_GET
    # Check that when an OpenID 2 response does not exceed the OpenID
    # 1 message size, a GET response (i.e., redirect) is issued.
    request = CheckIDRequest.new(
                                 'http://bombom.unittest/',
                                 'http://burr.unittest/999',
                                 'http://burr.unittest/',
                                 false,
                                 nil, @server.op_endpoint
                                 )
    response = OpenIDResponse.new(request)
    response.fields = Message.from_openid_args({
            'ns' => OPENID2_NS,
            'mode' => 'id_res',
            'identity' => request.identity,
            'claimed_id' => request.identity,
            'return_to' => request.return_to,
            })

    assert(!response.render_as_form)
    assert(response.which_encoding == ENCODE_URL)
    webresponse = @encode.call(response)
    assert(webresponse.headers.member?('location'))
  end

  def test_id_res_OpenID2_POST
    # Check that when an OpenID 2 response exceeds the OpenID 1
    # message size, a POST response (i.e., an HTML form) is returned.
    request = CheckIDRequest.new(
                                 'http://bombom.unittest/',
                                 'http://burr.unittest/999',
                                 'http://burr.unittest/',
                                 false,
                                 nil, @server.op_endpoint)
    response = OpenIDResponse.new(request)
    response.fields = Message.from_openid_args({
                                                 'ns' => OPENID2_NS,
                                                 'mode' => 'id_res',
                                                 'identity' => request.identity,
                                                 'claimed_id' => request.identity,
                                                 'return_to' => 'x' * OPENID1_URL_LIMIT,
                                               })

    assert(response.render_as_form)
    assert(response.encode_to_url.length > OPENID1_URL_LIMIT)
    assert(response.which_encoding == ENCODE_HTML_FORM)
    webresponse = @encode.call(response)
    assert_equal(webresponse.body, response.to_form_markup)
  end

  def test_id_res_OpenID1_exceeds_limit
    # Check that when an OpenID 1 response exceeds the OpenID 1
    # message size, a GET response is issued.  Technically, this
    # shouldn't be permitted by the library, but this test is in place
    # to preserve the status quo for OpenID 1.
    request = CheckIDRequest.new(
                                 'http://bombom.unittest/',
                                 'http://burr.unittest/999',
                                 'http://burr.unittest/',
                                 false,
                                 nil,
                                 @server.op_endpoint)

    response = OpenIDResponse.new(request)
    response.fields = Message.from_openid_args({
            'mode' => 'id_res',
            'identity' => request.identity,
            'return_to' => 'x' * OPENID1_URL_LIMIT,
            })

    assert(!response.render_as_form)
    assert(response.encode_to_url.length > OPENID1_URL_LIMIT)
    assert(response.which_encoding == ENCODE_URL)
    webresponse = @encode.call(response)
    assert_equal(webresponse.headers['location'], response.encode_to_url)
  end

  def test_id_res
    request = CheckIDRequest.new(
                                 'http://bombom.unittest/',
                                 'http://burr.unittest/999',
                                 'http://burr.unittest/',
                                 false, nil,
                                 @server.op_endpoint)
    response = OpenIDResponse.new(request)
    response.fields = Message.from_openid_args({
            'mode' => 'id_res',
            'identity' => request.identity,
            'return_to' => request.return_to,
            })
    webresponse = @encode.call(response)
    assert_equal(webresponse.code, HTTP_REDIRECT)
    assert(webresponse.headers.member?('location'))

    location = webresponse.headers['location']
    assert(location.starts_with?(request.return_to),
           sprintf("%s does not start with %s",
                   location, request.return_to))
    # argh.
    q2 = Util.parse_query(URI::parse(location).query)
    expected = response.fields.to_post_args
    assert_equal(q2, expected)
  end

  def test_cancel
    request = CheckIDRequest.new(
            'http://bombom.unittest/',
            'http://burr.unittest/999',
            'http://burr.unittest/',
            false, nil,
            @server.op_endpoint)
    response = OpenIDResponse.new(request)
    response.fields = Message.from_openid_args({
            'mode' => 'cancel',
            })
    webresponse = @encode.call(response)
    assert_equal(webresponse.code, HTTP_REDIRECT)
    assert(webresponse.headers.member?('location'))
  end

  def test_assocReply
    msg = Message.new(OPENID2_NS)
    msg.set_arg(OPENID2_NS, 'session_type', 'no-encryption')
    request = AssociateRequest.from_message(msg)
    response = OpenIDResponse.new(request)
    response.fields = Message.from_post_args(
            {'openid.assoc_handle' => "every-zig"})
    webresponse = @encode.call(response)
    body = "assoc_handle:every-zig\n"

    assert_equal(webresponse.code, HTTP_OK)
    assert_equal(webresponse.headers, {})
    assert_equal(webresponse.body, body)
  end

  def test_checkauthReply
    request = CheckAuthRequest.new('a_sock_monkey',
                                   'siggggg',
                                   [])
    response = OpenIDResponse.new(request)
    response.fields = Message.from_openid_args({
            'is_valid' => 'true',
            'invalidate_handle' => 'xXxX:xXXx'
            })
    body = "invalidate_handle:xXxX:xXXx\nis_valid:true\n"

    webresponse = @encode.call(response)
    assert_equal(webresponse.code, HTTP_OK)
    assert_equal(webresponse.headers, {})
    assert_equal(webresponse.body, body)
  end

  def test_unencodableError
    args = Message.from_post_args({
            'openid.identity' => 'http://limu.unittest/',
            })
    e = ProtocolError.new(args, "wet paint")
    assert_raise(EncodingError) {
      @encode.call(e)
    }
  end

  def test_encodableError
    args = Message.from_post_args({
            'openid.mode' => 'associate',
            'openid.identity' => 'http://limu.unittest/',
            })
    body="error:snoot\nmode:error\n"
    webresponse = @encode.call(ProtocolError.new(args, "snoot"))
    assert_equal(webresponse.code, HTTP_ERROR)
    assert_equal(webresponse.headers, {})
    assert_equal(webresponse.body, body)
  end
end

=begin

class TestSigningEncode(unittest.TestCase):
    def setUp(self):
        self._dumb_key = server.Signatory._dumb_key
        self._normal_key = server.Signatory._normal_key
        self.store = memstore.MemoryStore()
        self.server = server.Server(self.store, "http://signing.unittest/enc")
        self.request = server.CheckIDRequest(
            identity = 'http://bombom.unittest/',
            trust_root = 'http://burr.unittest/',
            return_to = 'http://burr.unittest/999',
            immediate = False,
            op_endpoint = self.server.op_endpoint,
            )
        self.response = server.OpenIDResponse(self.request)
        self.response.fields = Message.fromOpenIDArgs({
            'mode' => 'id_res',
            'identity' => self.request.identity,
            'return_to' => self.request.return_to,
            })
        self.signatory = server.Signatory(self.store)
        self.encoder = server.SigningEncoder(self.signatory)
        self.encode = self.encoder.encode

    def test_idres(self):
        assoc_handle = '{bicycle}{shed}'
        self.store.storeAssociation(
            self._normal_key,
            association.Association.fromExpiresIn(60, assoc_handle,
                                                  'sekrit', 'HMAC-SHA1'))
        self.request.assoc_handle = assoc_handle
        webresponse = self.encode(self.response)
        assert_equal(webresponse.code, server.HTTP_REDIRECT)
        assert(webresponse.headers.has_key('location'))

        location = webresponse.headers['location']
        query = cgi.parse_qs(urlparse(location)[4])
        assert('openid.sig' in query)
        assert('openid.assoc_handle' in query)
        assert('openid.signed' in query)

    def test_idresDumb(self):
        webresponse = self.encode(self.response)
        assert_equal(webresponse.code, server.HTTP_REDIRECT)
        assert(webresponse.headers.has_key('location'))

        location = webresponse.headers['location']
        query = cgi.parse_qs(urlparse(location)[4])
        assert('openid.sig' in query)
        assert('openid.assoc_handle' in query)
        assert('openid.signed' in query)

    def test_forgotStore(self):
        self.encoder.signatory = None
        self.failUnlessRaises(ValueError, self.encode, self.response)

    def test_cancel(self):
        request = server.CheckIDRequest(
            identity = 'http://bombom.unittest/',
            trust_root = 'http://burr.unittest/',
            return_to = 'http://burr.unittest/999',
            immediate = False,
            op_endpoint = self.server.op_endpoint,
            )
        response = server.OpenIDResponse(request)
        response.fields.setArg(OPENID_NS, 'mode', 'cancel')
        webresponse = self.encode(response)
        assert_equal(webresponse.code, server.HTTP_REDIRECT)
        assert(webresponse.headers.has_key('location'))
        location = webresponse.headers['location']
        query = cgi.parse_qs(urlparse(location)[4])
        self.failIf('openid.sig' in query, response.fields.toPostArgs())

    def test_assocReply(self):
        msg = Message(OPENID2_NS)
        msg.setArg(OPENID2_NS, 'session_type', 'no-encryption')
        request = server.AssociateRequest.fromMessage(msg)
        response = server.OpenIDResponse(request)
        response.fields = Message.fromOpenIDArgs({'assoc_handle' => "every-zig"})
        webresponse = self.encode(response)
        body = """assoc_handle:every-zig
"""
        assert_equal(webresponse.code, server.HTTP_OK)
        assert_equal(webresponse.headers, {})
        assert_equal(webresponse.body, body)

    def test_alreadySigned(self):
        self.response.fields.setArg(OPENID_NS, 'sig', 'priorSig==')
        self.failUnlessRaises(server.AlreadySigned, self.encode, self.response)

class TestCheckID(unittest.TestCase):
    def setUp(self):
        self.op_endpoint = 'http://endpoint.unittest/'
        self.store = memstore.MemoryStore()
        self.server = server.Server(self.store, self.op_endpoint)
        self.request = server.CheckIDRequest(
            identity = 'http://bambam.unittest/',
            trust_root = 'http://bar.unittest/',
            return_to = 'http://bar.unittest/999',
            immediate = False,
            op_endpoint = self.server.op_endpoint,
            )

    def test_trustRootInvalid(self):
        self.request.trust_root = "http://foo.unittest/17"
        self.request.return_to = "http://foo.unittest/39"
        self.failIf(self.request.trustRootValid())

    def test_trustRootValid(self):
        self.request.trust_root = "http://foo.unittest/"
        self.request.return_to = "http://foo.unittest/39"
        assert(self.request.trustRootValid())

    def test_trustRootValidNoReturnTo(self):
        request = server.CheckIDRequest(
            identity = 'http://bambam.unittest/',
            trust_root = 'http://bar.unittest/',
            return_to = None,
            immediate = False,
            op_endpoint = self.server.op_endpoint,
            )

        assert(request.trustRootValid())

    def test_returnToVerified_callsVerify(self):
        """Make sure that verifyReturnTo is calling the trustroot
        function verifyReturnTo
        """
        def withVerifyReturnTo(new_verify, callable):
            old_verify = server.verifyReturnTo
            try:
                server.verifyReturnTo = new_verify
                return callable()
            finally:
                server.verifyReturnTo = old_verify

        # Ensure that exceptions are passed through
        sentinel = Exception()
        def vrfyExc(trust_root, return_to):
            assert_equal(self.request.trust_root, trust_root)
            assert_equal(self.request.return_to, return_to)
            raise sentinel

        try:
            withVerifyReturnTo(vrfyExc, self.request.returnToVerified)
        except Exception, e:
            assert(e is sentinel, e)

        # Ensure that True and False are passed through unchanged
        def constVerify(val):
            def verify(trust_root, return_to):
                assert_equal(self.request.trust_root, trust_root)
                assert_equal(self.request.return_to, return_to)
                return val
            return verify

        for val in [True, False]:
            assert_equal(
                val,
                withVerifyReturnTo(constVerify(val),
                                   self.request.returnToVerified))

    def _expectAnswer(self, answer, identity=None, claimed_id=None):
        expected_list = [
            ('mode', 'id_res'),
            ('return_to', self.request.return_to),
            ('op_endpoint', self.op_endpoint),
            ]
        if identity:
            expected_list.append(('identity', identity))
            if claimed_id:
                expected_list.append(('claimed_id', claimed_id))
            else:
                expected_list.append(('claimed_id', identity))

        for k, expected in expected_list:
            actual = answer.fields.getArg(OPENID_NS, k)
            assert_equal(actual, expected, "%s: expected %s, got %s" % (k, expected, actual))

        assert(answer.fields.hasKey(OPENID_NS, 'response_nonce'))
        assert(answer.fields.getOpenIDNamespace() == OPENID2_NS)

        # One for nonce, one for ns
        assert_equal(len(answer.fields.toPostArgs()),
                             len(expected_list) + 2,
                             answer.fields.toPostArgs())


    def test_answerAllow(self):
        """Check the fields specified by "Positive Assertions"

        including mode=id_res, identity, claimed_id, op_endpoint, return_to
        """
        answer = self.request.answer(True)
        assert_equal(answer.request, self.request)
        self._expectAnswer(answer, self.request.identity)

    def test_answerAllowDelegatedIdentity(self):
        self.request.claimed_id = 'http://delegating.unittest/'
        answer = self.request.answer(True)
        self._expectAnswer(answer, self.request.identity,
                           self.request.claimed_id)

    def test_answerAllowWithoutIdentityReally(self):
        self.request.identity = None
        answer = self.request.answer(True)
        assert_equal(answer.request, self.request)
        self._expectAnswer(answer)

    def test_answerAllowAnonymousFail(self):
        self.request.identity = None
        # XXX - Check on this, I think this behavior is legal in OpenID 2.0?
        self.failUnlessRaises(
            ValueError, self.request.answer, True, identity="=V")

    def test_answerAllowWithIdentity(self):
        self.request.identity = IDENTIFIER_SELECT
        selected_id = 'http://anon.unittest/9861'
        answer = self.request.answer(True, identity=selected_id)
        self._expectAnswer(answer, selected_id)

    def test_answerAllowWithDelegatedIdentityOpenID2(self):
        """Answer an IDENTIFIER_SELECT case with a delegated identifier.
        """
        # claimed_id delegates to selected_id here.
        self.request.identity = IDENTIFIER_SELECT
        selected_id = 'http://anon.unittest/9861'
        claimed_id = 'http://monkeyhat.unittest/'
        answer = self.request.answer(True, identity=selected_id,
                                     claimed_id=claimed_id)
        self._expectAnswer(answer, selected_id, claimed_id)

    def test_answerAllowWithDelegatedIdentityOpenID1(self):
        """claimed_id parameter doesn't exist in OpenID 1.
        """
        self.request.namespace = OPENID1_NS
        # claimed_id delegates to selected_id here.
        self.request.identity = IDENTIFIER_SELECT
        selected_id = 'http://anon.unittest/9861'
        claimed_id = 'http://monkeyhat.unittest/'
        self.failUnlessRaises(server.VersionError,
                              self.request.answer, True,
                              identity=selected_id,
                              claimed_id=claimed_id)

    def test_answerAllowWithAnotherIdentity(self):
        # XXX - Check on this, I think this behavior is legal in OpenID 2.0?
        self.failUnlessRaises(ValueError, self.request.answer, True,
                              identity="http://pebbles.unittest/")

    def test_answerAllowNoIdentityOpenID1(self):
        self.request.namespace = OPENID1_NS
        self.request.identity = None
        self.failUnlessRaises(ValueError, self.request.answer, True,
                              identity=None)

    def test_answerAllowForgotEndpoint(self):
        self.request.op_endpoint = None
        self.failUnlessRaises(RuntimeError, self.request.answer, True)

    def test_checkIDWithNoIdentityOpenID1(self):
        msg = Message(OPENID1_NS)
        msg.setArg(OPENID_NS, 'return_to', 'bogus')
        msg.setArg(OPENID_NS, 'trust_root', 'bogus')
        msg.setArg(OPENID_NS, 'mode', 'checkid_setup')
        msg.setArg(OPENID_NS, 'assoc_handle', 'bogus')

        self.failUnlessRaises(server.ProtocolError,
                              server.CheckIDRequest.fromMessage,
                              msg, self.server)

    def test_trustRootOpenID1(self):
        """Ignore openid.realm in OpenID 1"""
        msg = Message(OPENID1_NS)
        msg.setArg(OPENID_NS, 'mode', 'checkid_setup')
        msg.setArg(OPENID_NS, 'trust_root', 'http://real_trust_root/')
        msg.setArg(OPENID_NS, 'realm', 'http://fake_trust_root/')
        msg.setArg(OPENID_NS, 'return_to', 'http://real_trust_root/foo')
        msg.setArg(OPENID_NS, 'assoc_handle', 'bogus')
        msg.setArg(OPENID_NS, 'identity', 'george')

        result = server.CheckIDRequest.fromMessage(msg, self.server.op_endpoint)

        assert(result.trust_root == 'http://real_trust_root/')

    def test_trustRootOpenID2(self):
        """Ignore openid.trust_root in OpenID 2"""
        msg = Message(OPENID2_NS)
        msg.setArg(OPENID_NS, 'mode', 'checkid_setup')
        msg.setArg(OPENID_NS, 'realm', 'http://real_trust_root/')
        msg.setArg(OPENID_NS, 'trust_root', 'http://fake_trust_root/')
        msg.setArg(OPENID_NS, 'return_to', 'http://real_trust_root/foo')
        msg.setArg(OPENID_NS, 'assoc_handle', 'bogus')
        msg.setArg(OPENID_NS, 'identity', 'george')
        msg.setArg(OPENID_NS, 'claimed_id', 'george')

        result = server.CheckIDRequest.fromMessage(msg, self.server.op_endpoint)

        assert(result.trust_root == 'http://real_trust_root/')

    def test_answerAllowNoTrustRoot(self):
        self.request.trust_root = None
        answer = self.request.answer(True)
        assert_equal(answer.request, self.request)
        self._expectAnswer(answer, self.request.identity)

    def test_answerImmediateDenyOpenID2(self):
        """Look for mode=setup_needed in checkid_immediate negative
        response in OpenID 2 case.

        See specification Responding to Authentication Requests /
        Negative Assertions / In Response to Immediate Requests.
        """
        self.request.mode = 'checkid_immediate'
        self.request.immediate = True
        server_url = "http://setup-url.unittest/"
        # crappiting setup_url, you dirty my interface with your presence!
        answer = self.request.answer(False, server_url=server_url)
        assert_equal(answer.request, self.request)
        assert_equal(len(answer.fields.toPostArgs()), 3, answer.fields)
        assert_equal(answer.fields.getOpenIDNamespace(), OPENID2_NS)
        assert_equal(answer.fields.getArg(OPENID_NS, 'mode'),
                             'setup_needed')
        # user_setup_url no longer required.

    def test_answerImmediateDenyOpenID1(self):
        """Look for user_setup_url in checkid_immediate negative
        response in OpenID 1 case."""
        self.request.namespace = OPENID1_NS
        self.request.mode = 'checkid_immediate'
        self.request.immediate = True
        server_url = "http://setup-url.unittest/"
        # crappiting setup_url, you dirty my interface with your presence!
        answer = self.request.answer(False, server_url=server_url)
        assert_equal(answer.request, self.request)
        assert_equal(len(answer.fields.toPostArgs()), 2, answer.fields)
        assert_equal(answer.fields.getOpenIDNamespace(), OPENID1_NS)
        assert_equal(answer.fields.getArg(OPENID_NS, 'mode'), 'id_res')
        assert(answer.fields.getArg(
            OPENID_NS, 'user_setup_url', '').startswith(server_url))

    def test_answerSetupDeny(self):
        answer = self.request.answer(False)
        assert_equal(answer.fields.getArgs(OPENID_NS), {
            'mode' => 'cancel',
            })

    def test_encodeToURL(self):
        server_url = 'http://openid-server.unittest/'
        result = self.request.encodeToURL(server_url)

        # How to check?  How about a round-trip test.
        base, result_args = result.split('?', 1)
        result_args = dict(cgi.parse_qsl(result_args))
        message = Message.fromPostArgs(result_args)
        rebuilt_request = server.CheckIDRequest.fromMessage(message,
                                                            self.server.op_endpoint)
        # argh, lousy hack
        self.request.message = message
        assert_equal(rebuilt_request.__dict__, self.request.__dict__)

    def test_getCancelURL(self):
        url = self.request.getCancelURL()
        rt, query_string = url.split('?')
        assert_equal(self.request.return_to, rt)
        query = dict(cgi.parse_qsl(query_string))
        assert_equal(query, {'openid.mode':'cancel',
                                     'openid.ns':OPENID2_NS})

    def test_getCancelURLimmed(self):
        self.request.mode = 'checkid_immediate'
        self.request.immediate = True
        self.failUnlessRaises(ValueError, self.request.getCancelURL)



class TestCheckIDExtension(unittest.TestCase):

    def setUp(self):
        self.op_endpoint = 'http://endpoint.unittest/ext'
        self.store = memstore.MemoryStore()
        self.server = server.Server(self.store, self.op_endpoint)
        self.request = server.CheckIDRequest(
            identity = 'http://bambam.unittest/',
            trust_root = 'http://bar.unittest/',
            return_to = 'http://bar.unittest/999',
            immediate = False,
            op_endpoint = self.server.op_endpoint,
            )
        self.response = server.OpenIDResponse(self.request)
        self.response.fields.setArg(OPENID_NS, 'mode', 'id_res')
        self.response.fields.setArg(OPENID_NS, 'blue', 'star')


    def test_addField(self):
        namespace = 'something:'
        self.response.fields.setArg(namespace, 'bright', 'potato')
        assert_equal(self.response.fields.getArgs(OPENID_NS),
                             {'blue' => 'star',
                              'mode' => 'id_res',
                              })
        
        assert_equal(self.response.fields.getArgs(namespace),
                             {'bright':'potato'})


    def test_addFields(self):
        namespace = 'mi5:'
        args =  {'tangy' => 'suspenders',
                 'bravo' => 'inclusion'}
        self.response.fields.updateArgs(namespace, args)
        assert_equal(self.response.fields.getArgs(OPENID_NS),
                             {'blue' => 'star',
                              'mode' => 'id_res',
                              })
        assert_equal(self.response.fields.getArgs(namespace), args)



class MockSignatory(object):
    isValid = True

    def __init__(self, assoc):
        self.assocs = [assoc]

    def verify(self, assoc_handle, message):
        assert message.hasKey(OPENID_NS, "sig")
        if (True, assoc_handle) in self.assocs:
            return self.isValid
        else:
            return False

    def getAssociation(self, assoc_handle, dumb):
        if (dumb, assoc_handle) in self.assocs:
            # This isn't a valid implementation for many uses of this
            # function, mind you.
            return True
        else:
            return None

    def invalidate(self, assoc_handle, dumb):
        if (dumb, assoc_handle) in self.assocs:
            self.assocs.remove((dumb, assoc_handle))


class TestCheckAuth(unittest.TestCase):
    def setUp(self):
        self.assoc_handle = 'mooooooooo'
        self.message = Message.fromPostArgs({
            'openid.sig' => 'signarture',
            'one' => 'alpha',
            'two' => 'beta',
            })
        self.request = server.CheckAuthRequest(
            self.assoc_handle, self.message)

        self.signatory = MockSignatory((True, self.assoc_handle))

    def test_valid(self):
        r = self.request.answer(self.signatory)
        assert_equal(r.fields.getArgs(OPENID_NS), {'is_valid' => 'true'})
        assert_equal(r.request, self.request)

    def test_invalid(self):
        self.signatory.isValid = False
        r = self.request.answer(self.signatory)
        assert_equal(r.fields.getArgs(OPENID_NS),
                             {'is_valid' => 'false'})

    def test_replay(self):
        """Don't validate the same response twice.

        From "Checking the Nonce"::
        
            When using "check_authentication", the OP MUST ensure that an
            assertion has not yet been accepted with the same value for
            "openid.response_nonce".

        In this implementation, the assoc_handle is only valid once.  And
        nonces are a signed component of the message, so they can't be used
        with another handle without breaking the sig.
        """
        r = self.request.answer(self.signatory)
        r = self.request.answer(self.signatory)
        assert_equal(r.fields.getArgs(OPENID_NS),
                             {'is_valid' => 'false'})

    def test_invalidatehandle(self):
        self.request.invalidate_handle = "bogusHandle"
        r = self.request.answer(self.signatory)
        assert_equal(r.fields.getArgs(OPENID_NS),
                             {'is_valid' => 'true',
                              'invalidate_handle' => "bogusHandle"})
        assert_equal(r.request, self.request)

    def test_invalidatehandleNo(self):
        assoc_handle = 'goodhandle'
        self.signatory.assocs.append((False, 'goodhandle'))
        self.request.invalidate_handle = assoc_handle
        r = self.request.answer(self.signatory)
        assert_equal(r.fields.getArgs(OPENID_NS), {'is_valid' => 'true'})


class TestAssociate(unittest.TestCase):
    # TODO: test DH with non-default values for modulus and gen.
    # (important to do because we actually had it broken for a while.)

    def setUp(self):
        self.request = server.AssociateRequest.fromMessage(
            Message.fromPostArgs({}))
        self.store = memstore.MemoryStore()
        self.signatory = server.Signatory(self.store)

    def test_dhSHA1(self):
        self.assoc = self.signatory.createAssociation(dumb=False, assoc_type='HMAC-SHA1')
        from openid.dh import DiffieHellman
        from openid.server.server import DiffieHellmanSHA1ServerSession
        consumer_dh = DiffieHellman.fromDefaults()
        cpub = consumer_dh.public
        server_dh = DiffieHellman.fromDefaults()
        session = DiffieHellmanSHA1ServerSession(server_dh, cpub)
        self.request = server.AssociateRequest(session, 'HMAC-SHA1')
        response = self.request.answer(self.assoc)
        rfg = lambda f: response.fields.getArg(OPENID_NS, f)
        assert_equal(rfg("assoc_type"), "HMAC-SHA1")
        assert_equal(rfg("assoc_handle"), self.assoc.handle)
        self.failIf(rfg("mac_key"))
        assert_equal(rfg("session_type"), "DH-SHA1")
        assert(rfg("enc_mac_key"))
        assert(rfg("dh_server_public"))

        enc_key = rfg("enc_mac_key").decode('base64')
        spub = cryptutil.base64ToLong(rfg("dh_server_public"))
        secret = consumer_dh.xorSecret(spub, enc_key, cryptutil.sha1)
        assert_equal(secret, self.assoc.secret)


    if not cryptutil.SHA256_AVAILABLE:
        warnings.warn("Not running SHA256 tests.")
    else:
        def test_dhSHA256(self):
            self.assoc = self.signatory.createAssociation(
                dumb=False, assoc_type='HMAC-SHA256')
            from openid.dh import DiffieHellman
            from openid.server.server import DiffieHellmanSHA256ServerSession
            consumer_dh = DiffieHellman.fromDefaults()
            cpub = consumer_dh.public
            server_dh = DiffieHellman.fromDefaults()
            session = DiffieHellmanSHA256ServerSession(server_dh, cpub)
            self.request = server.AssociateRequest(session, 'HMAC-SHA256')
            response = self.request.answer(self.assoc)
            rfg = lambda f: response.fields.getArg(OPENID_NS, f)
            assert_equal(rfg("assoc_type"), "HMAC-SHA256")
            assert_equal(rfg("assoc_handle"), self.assoc.handle)
            self.failIf(rfg("mac_key"))
            assert_equal(rfg("session_type"), "DH-SHA256")
            assert(rfg("enc_mac_key"))
            assert(rfg("dh_server_public"))

            enc_key = rfg("enc_mac_key").decode('base64')
            spub = cryptutil.base64ToLong(rfg("dh_server_public"))
            secret = consumer_dh.xorSecret(spub, enc_key, cryptutil.sha256)
            assert_equal(secret, self.assoc.secret)

        def test_protoError256(self):
            from openid.consumer.consumer import \
                 DiffieHellmanSHA256ConsumerSession

            s256_session = DiffieHellmanSHA256ConsumerSession()

            invalid_s256 = {'openid.assoc_type':'HMAC-SHA1',
                            'openid.session_type':'DH-SHA256',}
            invalid_s256.update(s256_session.getRequest())

            invalid_s256_2 = {'openid.assoc_type':'MONKEY-PIRATE',
                              'openid.session_type':'DH-SHA256',}
            invalid_s256_2.update(s256_session.getRequest())

            bad_request_argss = [
                invalid_s256,
                invalid_s256_2,
                ]

            for request_args in bad_request_argss:
                message = Message.fromPostArgs(request_args)
                self.failUnlessRaises(server.ProtocolError,
                                      server.AssociateRequest.fromMessage,
                                      message)

    def test_protoError(self):
        from openid.consumer.consumer import DiffieHellmanSHA1ConsumerSession
            
        s1_session = DiffieHellmanSHA1ConsumerSession()

        invalid_s1 = {'openid.assoc_type':'HMAC-SHA256',
                      'openid.session_type':'DH-SHA1',}
        invalid_s1.update(s1_session.getRequest())

        invalid_s1_2 = {'openid.assoc_type':'ROBOT-NINJA',
                      'openid.session_type':'DH-SHA1',}
        invalid_s1_2.update(s1_session.getRequest())

        bad_request_argss = [
            {'openid.assoc_type':'Wha?'},
            invalid_s1,
            invalid_s1_2,
            ]
            
        for request_args in bad_request_argss:
            message = Message.fromPostArgs(request_args)
            self.failUnlessRaises(server.ProtocolError,
                                  server.AssociateRequest.fromMessage,
                                  message)

    def test_protoErrorFields(self):

        contact = 'user@example.invalid'
        reference = 'Trac ticket number MAX_INT'
        error = 'poltergeist'

        openid1_args = {
            'openid.identitiy' => 'invalid',
            'openid.mode' => 'checkid_setup',
            }

        openid2_args = dict(openid1_args)
        openid2_args.update({'openid.ns' => OPENID2_NS})

        # Check presence of optional fields in both protocol versions

        openid1_msg = Message.fromPostArgs(openid1_args)
        p = server.ProtocolError(openid1_msg, error,
                                 contact=contact, reference=reference)
        reply = p.toMessage()

        assert_equal(reply.getArg(OPENID_NS, 'reference'), reference)
        assert_equal(reply.getArg(OPENID_NS, 'contact'), contact)

        openid2_msg = Message.fromPostArgs(openid2_args)
        p = server.ProtocolError(openid2_msg, error,
                                 contact=contact, reference=reference)
        reply = p.toMessage()

        assert_equal(reply.getArg(OPENID_NS, 'reference'), reference)
        assert_equal(reply.getArg(OPENID_NS, 'contact'), contact)

    def failUnlessExpiresInMatches(self, msg, expected_expires_in):
        expires_in_str = msg.getArg(OPENID_NS, 'expires_in', no_default)
        expires_in = int(expires_in_str)

        # Slop is necessary because the tests can sometimes get run
        # right on a second boundary
        slop = 1 # second
        difference = expected_expires_in - expires_in

        error_message = ('"expires_in" value not within %s of expected: '
                         'expected=%s, actual=%s' %
                         (slop, expected_expires_in, expires_in))
        assert(0 <= difference <= slop, error_message)

    def test_plaintext(self):
        self.assoc = self.signatory.createAssociation(dumb=False, assoc_type='HMAC-SHA1')
        response = self.request.answer(self.assoc)
        rfg = lambda f: response.fields.getArg(OPENID_NS, f)

        assert_equal(rfg("assoc_type"), "HMAC-SHA1")
        assert_equal(rfg("assoc_handle"), self.assoc.handle)

        self.failUnlessExpiresInMatches(
            response.fields, self.signatory.SECRET_LIFETIME)

        assert_equal(
            rfg("mac_key"), oidutil.toBase64(self.assoc.secret))
        self.failIf(rfg("session_type"))
        self.failIf(rfg("enc_mac_key"))
        self.failIf(rfg("dh_server_public"))

    def test_plaintext256(self):
        self.assoc = self.signatory.createAssociation(dumb=False, assoc_type='HMAC-SHA256')
        response = self.request.answer(self.assoc)
        rfg = lambda f: response.fields.getArg(OPENID_NS, f)

        assert_equal(rfg("assoc_type"), "HMAC-SHA1")
        assert_equal(rfg("assoc_handle"), self.assoc.handle)

        self.failUnlessExpiresInMatches(
            response.fields, self.signatory.SECRET_LIFETIME)

        assert_equal(
            rfg("mac_key"), oidutil.toBase64(self.assoc.secret))
        self.failIf(rfg("session_type"))
        self.failIf(rfg("enc_mac_key"))
        self.failIf(rfg("dh_server_public"))

    def test_unsupportedPrefer(self):
        allowed_assoc = 'COLD-PET-RAT'
        allowed_sess = 'FROG-BONES'
        message = 'This is a unit test'

        # Set an OpenID 2 message so answerUnsupported doesn't raise
        # ProtocolError.
        self.request.message = Message(OPENID2_NS)

        response = self.request.answerUnsupported(
            message=message,
            preferred_session_type=allowed_sess,
            preferred_association_type=allowed_assoc,
            )
        rfg = lambda f: response.fields.getArg(OPENID_NS, f)
        assert_equal(rfg('error_code'), 'unsupported-type')
        assert_equal(rfg('assoc_type'), allowed_assoc)
        assert_equal(rfg('error'), message)
        assert_equal(rfg('session_type'), allowed_sess)

    def test_unsupported(self):
        message = 'This is a unit test'

        # Set an OpenID 2 message so answerUnsupported doesn't raise
        # ProtocolError.
        self.request.message = Message(OPENID2_NS)

        response = self.request.answerUnsupported(message)
        rfg = lambda f: response.fields.getArg(OPENID_NS, f)
        assert_equal(rfg('error_code'), 'unsupported-type')
        assert_equal(rfg('assoc_type'), None)
        assert_equal(rfg('error'), message)
        assert_equal(rfg('session_type'), None)

class Counter(object):
    def __init__(self):
        self.count = 0

    def inc(self):
        self.count += 1

class TestServer(unittest.TestCase, CatchLogs):
    def setUp(self):
        self.store = memstore.MemoryStore()
        self.server = server.Server(self.store, "http://server.unittest/endpt")
        CatchLogs.setUp(self)

    def test_dispatch(self):
        monkeycalled = Counter()
        def monkeyDo(request):
            monkeycalled.inc()
            r = server.OpenIDResponse(request)
            return r
        self.server.openid_monkeymode = monkeyDo
        request = server.OpenIDRequest()
        request.mode = "monkeymode"
        request.namespace = OPENID1_NS
        webresult = self.server.handleRequest(request)
        assert_equal(monkeycalled.count, 1)

    def test_associate(self):
        request = server.AssociateRequest.fromMessage(Message.fromPostArgs({}))
        response = self.server.openid_associate(request)
        assert(response.fields.hasKey(OPENID_NS, "assoc_handle"),
                        "No assoc_handle here: %s" % (response.fields,))

    def test_associate2(self):
        """Associate when the server has no allowed association types

        Gives back an error with error_code and no fallback session or
        assoc types."""
        self.server.negotiator.setAllowedTypes([])

        # Set an OpenID 2 message so answerUnsupported doesn't raise
        # ProtocolError.
        msg = Message.fromPostArgs({
            'openid.ns' => OPENID2_NS,
            'openid.session_type' => 'no-encryption',
            })

        request = server.AssociateRequest.fromMessage(msg)

        response = self.server.openid_associate(request)
        assert(response.fields.hasKey(OPENID_NS, "error"))
        assert(response.fields.hasKey(OPENID_NS, "error_code"))
        self.failIf(response.fields.hasKey(OPENID_NS, "assoc_handle"))
        self.failIf(response.fields.hasKey(OPENID_NS, "assoc_type"))
        self.failIf(response.fields.hasKey(OPENID_NS, "session_type"))

    def test_associate3(self):
        """Request an assoc type that is not supported when there are
        supported types.

        Should give back an error message with a fallback type.
        """
        self.server.negotiator.setAllowedTypes([('HMAC-SHA256', 'DH-SHA256')])

        msg = Message.fromPostArgs({
            'openid.ns' => OPENID2_NS,
            'openid.session_type' => 'no-encryption',
            })

        request = server.AssociateRequest.fromMessage(msg)
        response = self.server.openid_associate(request)

        assert(response.fields.hasKey(OPENID_NS, "error"))
        assert(response.fields.hasKey(OPENID_NS, "error_code"))
        self.failIf(response.fields.hasKey(OPENID_NS, "assoc_handle"))
        assert_equal(response.fields.getArg(OPENID_NS, "assoc_type"),
                             'HMAC-SHA256')
        assert_equal(response.fields.getArg(OPENID_NS, "session_type"),
                             'DH-SHA256')

    if not cryptutil.SHA256_AVAILABLE:
        warnings.warn("Not running SHA256 tests.")
    else:
        def test_associate4(self):
            """DH-SHA256 association session"""
            self.server.negotiator.setAllowedTypes(
                [('HMAC-SHA256', 'DH-SHA256')])
            query = {
                'openid.dh_consumer_public':
                'ALZgnx8N5Lgd7pCj8K86T/DDMFjJXSss1SKoLmxE72kJTzOtG6I2PaYrHX'
                'xku4jMQWSsGfLJxwCZ6280uYjUST/9NWmuAfcrBfmDHIBc3H8xh6RBnlXJ'
                '1WxJY3jHd5k1/ZReyRZOxZTKdF/dnIqwF8ZXUwI6peV0TyS/K1fOfF/s',
                'openid.assoc_type' => 'HMAC-SHA256',
                'openid.session_type' => 'DH-SHA256',
                }
            message = Message.fromPostArgs(query)
            request = server.AssociateRequest.fromMessage(message)
            response = self.server.openid_associate(request)
            assert(response.fields.hasKey(OPENID_NS, "assoc_handle"))

    def test_missingSessionTypeOpenID2(self):
        """Make sure session_type is required in OpenID 2"""
        msg = Message.fromPostArgs({
            'openid.ns' => OPENID2_NS,
            })

        self.assertRaises(server.ProtocolError,
                          server.AssociateRequest.fromMessage, msg)

    def test_checkAuth(self):
        request = server.CheckAuthRequest('arrrrrf', '0x3999', [])
        response = self.server.openid_check_authentication(request)
        assert(response.fields.hasKey(OPENID_NS, "is_valid"))

class TestSignatory(unittest.TestCase, CatchLogs):
    def setUp(self):
        self.store = memstore.MemoryStore()
        self.signatory = server.Signatory(self.store)
        self._dumb_key = self.signatory._dumb_key
        self._normal_key = self.signatory._normal_key
        CatchLogs.setUp(self)

    def test_sign(self):
        request = server.OpenIDRequest()
        assoc_handle = '{assoc}{lookatme}'
        self.store.storeAssociation(
            self._normal_key,
            association.Association.fromExpiresIn(60, assoc_handle,
                                                  'sekrit', 'HMAC-SHA1'))
        request.assoc_handle = assoc_handle
        request.namespace = OPENID1_NS
        response = server.OpenIDResponse(request)
        response.fields = Message.fromOpenIDArgs({
            'foo' => 'amsigned',
            'bar' => 'notsigned',
            'azu' => 'alsosigned',
            })
        sresponse = self.signatory.sign(response)
        assert_equal(
            sresponse.fields.getArg(OPENID_NS, 'assoc_handle'),
            assoc_handle)
        assert_equal(sresponse.fields.getArg(OPENID_NS, 'signed'),
                             'assoc_handle,azu,bar,foo,signed')
        assert(sresponse.fields.getArg(OPENID_NS, 'sig'))
        self.failIf(self.messages, self.messages)

    def test_signDumb(self):
        request = server.OpenIDRequest()
        request.assoc_handle = None
        request.namespace = OPENID2_NS
        response = server.OpenIDResponse(request)
        response.fields = Message.fromOpenIDArgs({
            'foo' => 'amsigned',
            'bar' => 'notsigned',
            'azu' => 'alsosigned',
            'ns':OPENID2_NS,
            })
        sresponse = self.signatory.sign(response)
        assoc_handle = sresponse.fields.getArg(OPENID_NS, 'assoc_handle')
        assert(assoc_handle)
        assoc = self.signatory.getAssociation(assoc_handle, dumb=True)
        assert(assoc)
        assert_equal(sresponse.fields.getArg(OPENID_NS, 'signed'),
                             'assoc_handle,azu,bar,foo,ns,signed')
        assert(sresponse.fields.getArg(OPENID_NS, 'sig'))
        self.failIf(self.messages, self.messages)

    def test_signExpired(self):
        """Sign a response to a message with an expired handle (using invalidate_handle).

        From "Verifying with an Association"::

            If an authentication request included an association handle for an
            association between the OP and the Relying party, and the OP no
            longer wishes to use that handle (because it has expired or the
            secret has been compromised, for instance), the OP will send a
            response that must be verified directly with the OP, as specified
            in Section 11.3.2. In that instance, the OP will include the field
            "openid.invalidate_handle" set to the association handle that the
            Relying Party included with the original request.
        """
        request = server.OpenIDRequest()
        request.namespace = OPENID2_NS
        assoc_handle = '{assoc}{lookatme}'
        self.store.storeAssociation(
            self._normal_key,
            association.Association.fromExpiresIn(-10, assoc_handle,
                                                  'sekrit', 'HMAC-SHA1'))
        assert(self.store.getAssociation(self._normal_key, assoc_handle))

        request.assoc_handle = assoc_handle
        response = server.OpenIDResponse(request)
        response.fields = Message.fromOpenIDArgs({
            'foo' => 'amsigned',
            'bar' => 'notsigned',
            'azu' => 'alsosigned',
            })
        sresponse = self.signatory.sign(response)

        new_assoc_handle = sresponse.fields.getArg(OPENID_NS, 'assoc_handle')
        assert(new_assoc_handle)
        self.failIfEqual(new_assoc_handle, assoc_handle)

        assert_equal(
            sresponse.fields.getArg(OPENID_NS, 'invalidate_handle'),
            assoc_handle)

        assert_equal(sresponse.fields.getArg(OPENID_NS, 'signed'),
                             'assoc_handle,azu,bar,foo,invalidate_handle,signed')
        assert(sresponse.fields.getArg(OPENID_NS, 'sig'))

        # make sure the expired association is gone
        self.failIf(self.store.getAssociation(self._normal_key, assoc_handle),
                    "expired association is still retrievable.")

        # make sure the new key is a dumb mode association
        assert(self.store.getAssociation(self._dumb_key, new_assoc_handle))
        self.failIf(self.store.getAssociation(self._normal_key, new_assoc_handle))
        assert(self.messages)


    def test_signInvalidHandle(self):
        request = server.OpenIDRequest()
        request.namespace = OPENID2_NS
        assoc_handle = '{bogus-assoc}{notvalid}'

        request.assoc_handle = assoc_handle
        response = server.OpenIDResponse(request)
        response.fields = Message.fromOpenIDArgs({
            'foo' => 'amsigned',
            'bar' => 'notsigned',
            'azu' => 'alsosigned',
            })
        sresponse = self.signatory.sign(response)

        new_assoc_handle = sresponse.fields.getArg(OPENID_NS, 'assoc_handle')
        assert(new_assoc_handle)
        self.failIfEqual(new_assoc_handle, assoc_handle)

        assert_equal(
            sresponse.fields.getArg(OPENID_NS, 'invalidate_handle'),
            assoc_handle)

        assert_equal(
            sresponse.fields.getArg(OPENID_NS, 'signed'), 'assoc_handle,azu,bar,foo,invalidate_handle,signed')
        assert(sresponse.fields.getArg(OPENID_NS, 'sig'))

        # make sure the new key is a dumb mode association
        assert(self.store.getAssociation(self._dumb_key, new_assoc_handle))
        self.failIf(self.store.getAssociation(self._normal_key, new_assoc_handle))
        self.failIf(self.messages, self.messages)


    def test_verify(self):
        assoc_handle = '{vroom}{zoom}'
        assoc = association.Association.fromExpiresIn(
            60, assoc_handle, 'sekrit', 'HMAC-SHA1')

        self.store.storeAssociation(self._dumb_key, assoc)

        signed = Message.fromPostArgs({
            'openid.foo' => 'bar',
            'openid.apple' => 'orange',
            'openid.assoc_handle' => assoc_handle,
            'openid.signed' => 'apple,assoc_handle,foo,signed',
            'openid.sig' => 'uXoT1qm62/BB09Xbj98TQ8mlBco=',
            })

        verified = self.signatory.verify(assoc_handle, signed)
        self.failIf(self.messages, self.messages)
        assert(verified)


    def test_verifyBadSig(self):
        assoc_handle = '{vroom}{zoom}'
        assoc = association.Association.fromExpiresIn(
            60, assoc_handle, 'sekrit', 'HMAC-SHA1')

        self.store.storeAssociation(self._dumb_key, assoc)

        signed = Message.fromPostArgs({
            'openid.foo' => 'bar',
            'openid.apple' => 'orange',
            'openid.assoc_handle' => assoc_handle,
            'openid.signed' => 'apple,assoc_handle,foo,signed',
            'openid.sig' => 'uXoT1qm62/BB09Xbj98TQ8mlBco='.encode('rot13'),
            })

        verified = self.signatory.verify(assoc_handle, signed)
        self.failIf(self.messages, self.messages)
        self.failIf(verified)

    def test_verifyBadHandle(self):
        assoc_handle = '{vroom}{zoom}'
        signed = Message.fromPostArgs({
            'foo' => 'bar',
            'apple' => 'orange',
            'openid.sig' => "Ylu0KcIR7PvNegB/K41KpnRgJl0=",
            })

        verified = self.signatory.verify(assoc_handle, signed)
        self.failIf(verified)
        assert(self.messages)


    def test_verifyAssocMismatch(self):
        """Attempt to validate sign-all message with a signed-list assoc."""
        assoc_handle = '{vroom}{zoom}'
        assoc = association.Association.fromExpiresIn(
            60, assoc_handle, 'sekrit', 'HMAC-SHA1')

        self.store.storeAssociation(self._dumb_key, assoc)

        signed = Message.fromPostArgs({
            'foo' => 'bar',
            'apple' => 'orange',
            'openid.sig' => "d71xlHtqnq98DonoSgoK/nD+QRM=",
            })

        verified = self.signatory.verify(assoc_handle, signed)
        self.failIf(verified)
        assert(self.messages)

    def test_getAssoc(self):
        assoc_handle = self.makeAssoc(dumb=True)
        assoc = self.signatory.getAssociation(assoc_handle, True)
        assert(assoc)
        assert_equal(assoc.handle, assoc_handle)
        self.failIf(self.messages, self.messages)

    def test_getAssocExpired(self):
        assoc_handle = self.makeAssoc(dumb=True, lifetime=-10)
        assoc = self.signatory.getAssociation(assoc_handle, True)
        self.failIf(assoc, assoc)
        assert(self.messages)

    def test_getAssocInvalid(self):
        ah = 'no-such-handle'
        assert_equal(
            self.signatory.getAssociation(ah, dumb=False), None)
        self.failIf(self.messages, self.messages)

    def test_getAssocDumbVsNormal(self):
        """getAssociation(dumb=False) cannot get a dumb assoc"""
        assoc_handle = self.makeAssoc(dumb=True)
        assert_equal(
            self.signatory.getAssociation(assoc_handle, dumb=False), None)
        self.failIf(self.messages, self.messages)

    def test_getAssocNormalVsDumb(self):
        """getAssociation(dumb=True) cannot get a shared assoc

        From "Verifying Directly with the OpenID Provider"::

            An OP MUST NOT verify signatures for associations that have shared
            MAC keys.
        """
        assoc_handle = self.makeAssoc(dumb=False)
        assert_equal(
            self.signatory.getAssociation(assoc_handle, dumb=True), None)
        self.failIf(self.messages, self.messages)

    def test_createAssociation(self):
        assoc = self.signatory.createAssociation(dumb=False)
        assert(self.signatory.getAssociation(assoc.handle, dumb=False))
        self.failIf(self.messages, self.messages)

    def makeAssoc(self, dumb, lifetime=60):
        assoc_handle = '{bling}'
        assoc = association.Association.fromExpiresIn(lifetime, assoc_handle,
                                                      'sekrit', 'HMAC-SHA1')

        self.store.storeAssociation((dumb and self._dumb_key) or self._normal_key, assoc)
        return assoc_handle

    def test_invalidate(self):
        assoc_handle = '-squash-'
        assoc = association.Association.fromExpiresIn(60, assoc_handle,
                                                      'sekrit', 'HMAC-SHA1')

        self.store.storeAssociation(self._dumb_key, assoc)
        assoc = self.signatory.getAssociation(assoc_handle, dumb=True)
        assert(assoc)
        assoc = self.signatory.getAssociation(assoc_handle, dumb=True)
        assert(assoc)
        self.signatory.invalidate(assoc_handle, dumb=True)
        assoc = self.signatory.getAssociation(assoc_handle, dumb=True)
        self.failIf(assoc)
        self.failIf(self.messages, self.messages)

=end
