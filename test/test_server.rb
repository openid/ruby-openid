require 'test/unit'
require 'uri'

require 'openid/server'
require 'openid/stores'

include OpenID::Server

ALT_MODULUS = 0xCAADDDEC1667FC68B5FA15D53C4E1532DD24561A1A2D47A12C01ABEA1E00731F6921AAC40742311FDF9E634BB7131BEE1AF240261554389A910425E044E88C8359B010F5AD2B80E29CB1A5B027B19D9E01A6F63A6F45E5D7ED2FF6A2A0085050A7D0CF307C3DB51D2490355907B4427C23A98DF1EB8ABEF2BA209BB7AFFE86A7
ALT_GEN = 5

class TestProtocolError < Test::Unit::TestCase
  
  def test_browser_with_return_to
    return_to = 'http://rp.unittest/consumer'
    # will be a ProtocolError raised by Decode or CheckAuthRequest.answer
    args = {
      'openid.mode' => 'monkeydance',
      'openid.identity' => 'http://wagu.unittest/',
      'openid.return_to' => return_to
    }
    e = ProtocolError.new(args, 'plucky')
    
    assert_equal(true, e.has_return_to?)

    expected_args = {
      'openid.mode' => 'error',
      'openid.error' => 'plucky'
    }

    actual_args = OpenID::Util.parse_query(URI.parse(e.encode_to_url).query)
    assert_equal(expected_args, actual_args)
    assert_equal(ENCODE_URL, e.which_encoding?)
  end

  def test_no_return_to
    args = {
      'openid.mode' => 'zebradance',
      'openid.identity' => 'http://wagu.unittest/',
    }
    
    e = ProtocolError.new(args, "waffles")
    assert_equal(false, e.has_return_to?)
    
    expected = {
      'error' => 'waffles',
      'mode' => 'error'
    }
    
    actual = OpenID::Util.parsekv(e.encode_to_kvform)
    assert_equal(expected, actual)
    assert_equal(ENCODE_KVFORM, e.which_encoding?)
  end

end

class TestDecode < Test::Unit::TestCase
  
  def setup
    @id_url = "http://decoder.am.unittest/"
    @rt_url = "http://rp.unittest/foobot/?qux=zam"
    @tr_url = "http://rp.unittest/"
    @assoc_handle = "{assoc}{handle}"
  end

  def decode(args)
    Decoder.new.decode(args)
  end

  def test_nil
    args = {}
    r = self.decode(args)
    assert_equal(nil, r)
  end

  def test_irrelevant
    args = {
      'pony' => 'spotted',
      'sreg.mutant_power' => 'decaffinator',
    }
    r = self.decode(args)
    assert_equal(nil, r)
  end

  def test_bad
      args = {
      'openid.mode' => 'twos-compliment',
      'openid.pants' => 'zippered'
    }

    begin
      self.decode(args)
    rescue ProtocolError
      assert true
    else
      assert false, 'failed to raise ProtocolError'
    end
  end

  def test_dict_of_lists
    args = {
      'openid.mode' => ['checkid_setup'],
      'openid.identity' => @id_url,
      'openid.assoc_handle' => @assoc_handle,
      'openid.return_to' => @rt_url,
      'openid.trust_root' => @tr_url
    }
    
    # this should raise an argument error
    begin
      result = self.decode(args)
    rescue ArgumentError
      assert true
    end
  end


  def test_checkid_immediate
    args = {
      'openid.mode' => 'checkid_immediate',
      'openid.identity' => @id_url,
      'openid.assoc_handle' => @assoc_handle,
      'openid.return_to' => @rt_url,
      'openid.trust_root' => @tr_url,
      # should be ignored
      'openid.some.extension' => 'junk'
    }

    r = self.decode(args)

    assert_equal(CheckIDRequest, r.class)
    assert_equal('checkid_immediate', r.mode)
    assert_equal(true, r.immediate)
    assert_equal(@id_url, r.identity)
    assert_equal(@tr_url, r.trust_root)
    assert_equal(@rt_url, r.return_to)
    assert_equal(@assoc_handle, r.assoc_handle)
  end

  def test_checkid_setup_no_identity
    args = {
      'openid.mode' => 'checkid_setup',
      'openid.assoc_handle' => @assoc_handle,
      'openid.return_to' => @rt_url,
      'openid.trust_root' => @tr_url,
    }

    begin
      result = self.decode(args)
    rescue ProtocolError => e
      assert e.query == args
    else
      flunk('Expected a ProtocolError, but did not get one')
    end
  end


  def test_checkid_setup_no_return_to
    args = {
      'openid.mode' => 'checkid_setup',
      'openid.identity' => @id_url,
      'openid.assoc_handle' => @assoc_handle,
      'openid.trust_root' => @tr_url,
    }
    begin
      result = self.decode(args)
    rescue ProtocolError => e
      assert e.query == args
    else
      flunk('Expected a ProtocolError, but did not get one')
    end
  end

  def test_checkid_setup_bad_return_to
    args = {
      'openid.mode' => 'checkid_setup',
      'openid.identity' => @id_url,
      'openid.assoc_handle' => @assoc_handle,
      'openid.return_to' => 'not a url',
      'openid.trust_root' => @tr_url,
    }
    begin
      result = self.decode(args)
    rescue MalformedReturnURL => e
      assert e.query == args
    else
      flunk('Expected a MalformedReturnURL, but did not get one')
    end
  end

  def test_checkid_setup_untrusted_return_to
    args = {
      'openid.mode' => 'checkid_setup',
      'openid.identity' => @id_url,
      'openid.assoc_handle' => @assoc_handle,
      'openid.return_to' => 'http://incorrect.example.com/',
      'openid.trust_root' => @tr_url,
    }
    begin
      result = self.decode(args)
    rescue UntrustedReturnURL => e
      assert true
    else
      flunk('Expected a UntrustedReturnURL, but did not get one')
    end
  end


  def test_check_auth
    args = {
      'openid.mode' => 'check_authentication',
      'openid.assoc_handle' => '{dumb}{handle}',
      'openid.sig' => 'sigblob',
      'openid.signed' => 'foo,bar,mode',
      'openid.foo' => 'signedval1',
      'openid.bar' => 'signedval2',
      'openid.baz' => 'unsigned',
    }
    r = self.decode(args)
    assert_equal(r.class, CheckAuthRequest)
    assert_equal('check_authentication', r.mode)
    assert_equal('sigblob', r.sig)
    assert_equal([['foo', 'signedval1'],
                  ['bar', 'signedval2'],
                  ['mode', 'id_res']], r.signed)
                           
  end

  def test_check_auth_missing_signed_field
    args = {
      'openid.mode' => 'check_authentication',
      'openid.assoc_handle' => '{dumb}{handle}',
      'openid.sig' => 'sigblob',
      'openid.signed' => 'foo,bar,mode',
      'openid.foo' => 'signedval1',
      'openid.baz' => 'unsigned'
    }
    begin
      r = self.decode(args)
    rescue ProtocolError => e
      assert e.query == args
    else
      flunk('Expected a ProtocolError, but did not get one')
    end
  end

  def test_check_auth_missing_signature
    args = {
      'openid.mode' => 'check_authentication',
      'openid.assoc_handle' => '{dumb}{handle}',
      'openid.signed' => 'foo,bar,mode',
      'openid.foo' => 'signedval1',
      'openid.bar' => 'signedval2',
      'openid.baz' => 'unsigned'
    }
    begin
      r = self.decode(args)
    rescue ProtocolError => e
      assert e.query == args
    else
      flunk('Expected a ProtocolError, but did not get one')
    end
  end
  

  def test_check_auth_and_invalidate
    args = {
      'openid.mode' => 'check_authentication',
      'openid.assoc_handle' => '{dumb}{handle}',
      'openid.invalidate_handle' => '[[SMART_handle]]',
      'openid.sig' => 'sigblob',
      'openid.signed' => 'foo,bar,mode',
      'openid.foo' => 'signedval1',
      'openid.bar' => 'signedval2',
      'openid.baz' => 'unsigned'
    }
    r = self.decode(args)
    assert_equal(CheckAuthRequest, r.class)
    assert_equal('[[SMART_handle]]', r.invalidate_handle)
  end


  def test_associate_DH
    args = {
      'openid.mode' => 'associate',
      'openid.session_type' => 'DH-SHA1',
      'openid.dh_consumer_public' => "Rzup9265tw=="
    }
    r = self.decode(args)
    assert_equal(AssociateRequest, r.class)
    assert_equal("associate", r.mode)
    assert_equal("DH-SHA1", r.session.session_type)
    assert_equal("HMAC-SHA1", r.assoc_type)
    assert(r.session.consumer_pubkey)
  end

  # Trying DH assoc w/o public key
  def test_associate_DH_missing_key
    args = {
      'openid.mode' => 'associate',
      'openid.session_type' => 'DH-SHA1'
    }
    # Using DH-SHA1 without supplying dh_consumer_public is an error.
    begin
      self.decode(args)
    rescue ProtocolError => e
      assert e.query == args
    else
      flunk('Wanted a ProtocolError')
    end
  end

  # test associate w/ non default mod and gen
  def test_associate_DH_mod_gen
    args = {
      'openid.mode' => 'associate',
      'openid.session_type' => 'DH-SHA1',
      'openid.dh_consumer_public' => "Rzup9265tw==",
      'openid.dh_modulus' => OpenID::Util.num_to_base64(ALT_MODULUS),
      'openid.dh_gen' => OpenID::Util.num_to_base64(ALT_GEN)
    }
    r = self.decode(args)
    assert_equal(AssociateRequest, r.class)
    assert_equal('DH-SHA1', r.session.session_type)
    assert_equal('HMAC-SHA1', r.assoc_type)
    assert_equal(ALT_MODULUS, r.session.dh.p)
    assert_equal(ALT_GEN, r.session.dh.g)
    assert r.session.consumer_pubkey
  end

  def test_associate_weird_session
    args = {
      'openid.mode' => 'associate',
      'openid.session_type' => 'FLCL6',
      'openid.dh_consumer_public' => "YQ==\n"
    }
    begin
      self.decode(args)
    rescue ProtocolError => e
      assert e.query == args
    else
      flunk('Wanted a ProtocolError')
    end      
  end

  def test_associate_plain_session
    args = {'openid.mode' => 'associate'}
    r = self.decode(args)
    assert_equal(AssociateRequest, r.class)
    assert_equal('associate', r.mode)
    assert_equal('plaintext', r.session.session_type)
    assert_equal('HMAC-SHA1', r.assoc_type)
  end

end

class TestEncode < Test::Unit::TestCase
  
  def setup
    @encoder = Encoder.new
  end

  def test_id_res
    request = CheckIDRequest.new('checkid_setup',
                                 'http://bombom.unittest/',
                                 'http://burr.unittest/999',
                                 'http://burr.unittest/')
    response = OpenIDResponse.new(request)
    response.fields = {
      'mode' => 'id_res',
      'identity' => request.identity,
      'return_to' => request.return_to
    }
    webresponse = @encoder.encode(response)
    assert_equal(HTTP_REDIRECT, webresponse.code)
    assert webresponse.headers.has_key?('location')    
    loc = webresponse.headers['location']
    assert loc.starts_with?(request.return_to)

    query = OpenID::Util.parse_query(URI.parse(loc).query)
    expected = {}
    response.fields.each {|k,v| expected['openid.'+k] = v}
    assert_equal(expected, query)
  end

  def test_cancel
    request = CheckIDRequest.new('checkid_setup',
                                 'http://bombom.unittest/',
                                 'http://burr.unittest/999',
                                 'http://burr.unittest/')
    response = OpenIDResponse.new(request)
    response.fields = {'mode' => 'cancel'}
    wr = @encoder.encode(response)
    assert_equal(HTTP_REDIRECT, wr.code)
    assert wr.headers.has_key?('location')
    assert wr.headers['location'].starts_with?(request.return_to)
  end

  def test_assoc_reply
    req = AssociateRequest.from_query({})
    resp = OpenIDResponse.new(req)
    resp.fields = {'assoc_handle' => 'every-zig'}
    wr = @encoder.encode(resp)
    assert_equal(HTTP_OK, wr.code)
    assert_equal({}, wr.headers)
    assert_equal("assoc_handle:every-zig\n", wr.body)
  end

  def test_check_auth_reply
    req = CheckAuthRequest.new('sock', 'sigg', [])
    res = OpenIDResponse.new(req)
    res.fields = {'is_valid' => 'true', 'invalidate_handle' => 'xxx:xxx'}
    wr = @encoder.encode(res)
    
    expected = "invalidate_handle:xxx:xxx\nis_valid:true\n"
    expected = OpenID::Util.parsekv(expected)

    assert_equal(HTTP_OK, wr.code)
    assert_equal({}, wr.headers)
    assert_equal(expected, OpenID::Util.parsekv(wr.body))
  end

  def test_unencodable_error
    args = {'openid.identity' => 'http://limu.unittest/'}
    e = ProtocolError.new(args, 'foo')
    begin
      @encoder.encode(e)
    rescue EncodingError => e
      assert true
    else
      flunk('Expected an EncodingError')
    end
  end

  def test_encodable_error
    args = {
      'openid.mode' => 'associate',
      'openid.identity' => 'http://limu.unittest/'
    }
    e = ProtocolError.new(args, 'snoot')

    expected_body = "error:snoot\nmode:error\n"
    expected_body = OpenID::Util.parsekv(expected_body)   
    
    wr = @encoder.encode(e)
    assert_equal(HTTP_ERROR, wr.code)
    assert_equal({}, wr.headers)
    assert_equal(expected_body, OpenID::Util.parsekv(wr.body))
  end

end

class TestSigningEncode < Test::Unit::TestCase

  def setup
    @dumb_key = 'http://localhost/|dumb'
    @normal_key = 'http://localhost/|normal'
    @store = OpenID::MemoryStore.new
    @request = CheckIDRequest.new('checkid_setup',
                                  'http://bombom.unittest/',
                                  'http://burr.unittest/999',
                                  'http://burr.unittest/')
    @response = OpenIDResponse.new(@request)
    @response.fields = {
      'mode' => 'id_res',
      'identity' => @request.identity,
      'return_to' => @request.return_to
    }
    @response.signed += ['mode','identity','return_to']
    @signatory = Signatory.new(@store)
    @encoder = SigningEncoder.new(@signatory)
  end

  def test_id_res
    assoc_handle = '{bicycle}{shed}'
    assoc = OpenID::Association.from_expires_in(60, assoc_handle,
                                                'sekrit','HMAC-SHA1')
    @store.store_association(@normal_key, assoc)
    @request.assoc_handle = assoc_handle
    wr = @encoder.encode(@response)
    
    assert_equal(HTTP_REDIRECT, wr.code)
    assert wr.headers.has_key?('location')
    
    loc = wr.headers['location']
    query = OpenID::Util.parse_query(URI.parse(loc).query)

    assert query.has_key?('openid.sig')
    assert query.has_key?('openid.signed')
    assert query.has_key?('openid.assoc_handle')
  end

  def test_id_res_dumb
    wr = @encoder.encode(@response)

    assert_equal(HTTP_REDIRECT, wr.code)
    assert wr.headers.has_key?('location')

    loc = wr.headers['location']
    query = OpenID::Util.parse_query(URI.parse(loc).query)
    
    assert query.has_key?('openid.sig')
    assert query.has_key?('openid.signed')
    assert query.has_key?('openid.assoc_handle')
  end

  def test_cancel
    response = OpenIDResponse.new(@request)
    response.fields['mode'] = 'cancel'
    response.signed.clear
    wr = @encoder.encode(response)
    assert_equal(HTTP_REDIRECT, wr.code)
    assert wr.headers.has_key?('location')

    loc = wr.headers['location']
    query = OpenID::Util.parse_query(URI.parse(loc).query)
    assert(!query.has_key?('openid.sig'))
  end

  def test_assoc_reply
    req = AssociateRequest.from_query({})
    res = OpenIDResponse.new(req)
    res.fields = {'assoc_handle' => 'every-zig'}
    wr = @encoder.encode(res)
    assert_equal(HTTP_OK, wr.code)
    assert_equal({}, wr.headers)
    assert_equal("assoc_handle:every-zig\n", wr.body)
  end

  def test_already_signed
    @response.fields['sig'] = 'priorSig=='
    begin
      @encoder.encode(@response)
    rescue AlreadySigned => e
      assert true
    else
      flunk('Wanted an AlreadySigned exception')
    end
  end

end

class TestCheckID < Test::Unit::TestCase
  
  def setup
    @request = CheckIDRequest.new('checkid_setup',
                                  'http://bombom.unittest/',
                                  'http://burr.unittest/999',
                                  'http://burr.unittest/')    
  end

  def test_trust_root_invalid
    @request.trust_root = 'http://foo.un/17'
    @request.return_to = 'http://foo.un/39'
    assert !@request.trust_root_valid
  end

  def test_trust_root_hvalid
    @request.trust_root = 'http://foo.un/'
    @request.return_to = 'http://foo.un/39'
    assert @request.trust_root_valid
  end

  def test_answer_allow
    answer = @request.answer(true)
    assert_equal(@request, answer.request)
    assert_equal({'mode'=>'id_res','identity'=>@request.identity,
                   'return_to'=>@request.return_to}, answer.fields)
    signed = answer.signed.dup.sort
    assert_equal(['identity','mode','return_to'], signed)
  end
  
  def test_answer_allow_no_trust_root
    @request.trust_root = nil
    answer = @request.answer(true)
    assert_equal(@request, answer.request)
    assert_equal({'mode'=>'id_res','identity'=>@request.identity,
                   'return_to'=>@request.return_to}, answer.fields)
    signed = answer.signed.dup.sort
    assert_equal(['identity','mode','return_to'], signed)
  end

  def test_answer_immediate_deny
    @request.mode = 'checkid_immediate'
    @request.immediate = true
    server_url = 'http://server-url.unittest/'
    answer = @request.answer(false, server_url)
    assert_equal(@request, answer.request)
    assert_equal(2, answer.fields.length)
    assert_equal('id_res', answer.fields['mode'])
    assert answer.fields['user_setup_url'].starts_with?(server_url)
    assert_equal([], answer.signed)
  end

  def test_answer_setup_deny
    answer = @request.answer(false)
    assert_equal({'mode' => 'cancel'}, answer.fields)
    assert_equal([], answer.signed)
  end

  def test_encode_to_url
    server_url = 'http://openid-server.un/'
    url = @request.encode_to_url(server_url)
    query = OpenID::Util.parse_query(URI.parse(url).query)
    
    req = CheckIDRequest.from_query(query)
    assert_equal(@request.mode, req.mode)
    assert_equal(@request.identity, req.identity)
    assert_equal(@request.return_to, req.return_to)
    assert_equal(@request.trust_root, req.trust_root)
    assert_equal(@request.immediate, req.immediate)
    assert_equal(@request.assoc_handle, req.assoc_handle)
  end

  def test_cancel_url
    url = @request.cancel_url
    expected = OpenID::Util.append_args(@request.return_to, 
                                        {'openid.mode'=>'cancel'})
    assert_equal(expected, url)
  end
  
  def test_cancel_url_immediate
    @request.immediate = true
    begin
      url = @request.cancel_url
    rescue ProtocolError => e
      assert true
    else
      flunk('Wanted a ProtoclError')
    end
  end

end


class TestCheckIDExtension < Test::Unit::TestCase
  
  def setup
    @request = CheckIDRequest.new('checkid_setup',
                                  'http://bombom.unittest/',
                                  'http://burr.unittest/999',
                                  'http://burr.unittest/')
    @response = OpenIDResponse.new(@request)
    @response.fields['mode'] = 'id_res'
    @response.fields['blue'] = 'star'
    @response.signed += ['mode','identity','return_to']
  end

  def test_add_field
    ns = 'mj12'
    @response.add_field(ns, 'bright', 'potato')
    assert_equal({'blue'=>'star',
                 'mode'=>'id_res',
                 'mj12.bright'=>'potato'}, @response.fields)
    assert_equal(['mode','identity','return_to','mj12.bright'], @response.signed)    
  end

  def test_add_field_unsigned
    ns = 'mj12'
    @response.add_field(ns, 'bright', 'potato', false)
    assert_equal({'blue'=>'star',
                 'mode'=>'id_res',
                 'mj12.bright'=>'potato'}, @response.fields)
    assert_equal(['mode','identity','return_to'], @response.signed)    
  end

  def test_add_fields
    ns = 'mj12'
    @response.add_fields(ns, {'bright'=>'potato', 'xxx'=>'yyy'})
    assert_equal({'blue'=>'star',
                 'mode'=>'id_res',
                 'mj12.bright'=>'potato',
                 'mj12.xxx'=>'yyy'}, @response.fields)
    assert_equal(['mode','identity','return_to','mj12.bright','mj12.xxx'].sort, @response.signed.sort)    
  end

  def test_add_fields_unsigned
    ns = 'mj12'
    @response.add_fields(ns, {'bright'=>'potato', 'xxx'=>'yyy'}, false)
    assert_equal({'blue'=>'star',
                 'mode'=>'id_res',
                 'mj12.bright'=>'potato',
                 'mj12.xxx'=>'yyy'}, @response.fields)
    assert_equal(['mode','identity','return_to'].sort, @response.signed.sort)    
  end

  def test_update
    eres = OpenIDResponse.new(nil)
    eres.fields.update({'a'=>'b','c'=>'d'})
    eres.signed = ['c']
    
    @response.update('ns', eres)
    assert_equal({'blue'=>'star','mode'=>'id_res','ns.a'=>'b','ns.c'=>'d'},
                 @response.fields)
    assert_equal(['mode', 'identity', 'return_to', 'ns.c'], @response.signed)
  end
  
  def test_update_no_namespace
    eres = OpenIDResponse.new(nil)
    eres.fields.update({'a'=>'b','c'=>'d'})
    eres.signed = ['c']
    
    @response.update(nil, eres)
    assert_equal({'blue'=>'star','mode'=>'id_res','a'=>'b','c'=>'d'},
                 @response.fields)
    assert_equal(['mode', 'identity', 'return_to', 'c'], @response.signed)
  end

end

class MockSignatory
  
  attr_accessor :is_valid, :assocs

  def initialize(assoc)
    @assocs = [assoc]
    @is_valid = true
  end

  def is_valid?
    @is_valid
  end

  def verify(assoc_handle, sig, signed_pairs)
    if @assocs.member?([true, assoc_handle])
      return self.is_valid?
    else
      return false
    end
  end

  def get_association(assoc_handle, dumb)
    if @assocs.member?([dumb, assoc_handle])
      return true
    else
      return nil
    end
  end

  def invalidate(assoc_handle, dumb)
    @assocs.delete([dumb, assoc_handle])
  end

end

class TestCheckAuthServer < Test::Unit::TestCase

  def setup
    @assoc_handle = 'moo'
    @request = CheckAuthRequest.new(@assoc_handle, 'signature',
                                    [['one','alpha'],['two','beta']])
    @signatory = MockSignatory.new([true, @assoc_handle])
  end

  def test_valid
    r = @request.answer(@signatory)
    assert_equal({'is_valid'=>'true'}, r.fields)
    assert_equal(r.request, @request)
  end

  def test_invalid
    assert_not_nil(@signatory)

    @signatory.is_valid = false
    r = @request.answer(@signatory)
    assert_equal({'is_valid'=>'false'}, r.fields)
    assert_equal(r.request, @request)
  end

  def test_replay
    r = @request.answer(@signatory)
    r = @request.answer(@signatory)
    assert_equal({'is_valid'=>'false'}, r.fields)
  end

  def test_invalidate_handle
    @request.invalidate_handle = 'bogushandle'
    r = @request.answer(@signatory)
    assert_equal({'is_valid'=>'true',
                 'invalidate_handle'=>'bogushandle'}, r.fields)
    assert_equal(r.request, @request)    
  end

  def test_invalidate_handle_no
    assoc_handle = 'goodhandle'
    @signatory.assocs << [false, assoc_handle]
    @request.invalidate_handle = assoc_handle
    r = @request.answer(@signatory)
    assert_equal({'is_valid'=>'true'}, r.fields)
  end

end


class TestAssociate < Test::Unit::TestCase
  
  def setup
    @request = AssociateRequest.from_query({})
    @store = OpenID::MemoryStore.new
    @signatory = Signatory.new(@store)
    @assoc = @signatory.create_association(false)
  end

  def test_dh
    consumer_dh = OpenID::DiffieHellman.new
    cpub = consumer_dh.public
    session = DiffieHellmanServerSession.new(OpenID::DiffieHellman.new, cpub)
    @request = AssociateRequest.new(session)
    response = @request.answer(@assoc)
    rf = response.fields
    assert_equal('HMAC-SHA1', rf['assoc_type'])
    assert_equal('DH-SHA1', rf['session_type'])
    assert_equal(@assoc.handle, rf['assoc_handle'])
    assert_nil(rf['mac_key'])
    assert_not_nil(rf['enc_mac_key'])
    assert_not_nil(rf['dh_server_public'])

    enc_key = OpenID::Util.from_base64(rf['enc_mac_key'])
    spub = OpenID::Util.base64_to_num(rf['dh_server_public'])
    secret = consumer_dh.xor_secrect(spub, enc_key)
    assert_equal(@assoc.secret, secret)
  end

  def test_plaintext
    response = @request.answer(@assoc)
    rf = response.fields
    
    assert_equal('HMAC-SHA1', rf['assoc_type'])
    assert_equal(@assoc.handle, rf['assoc_handle'])
    assert_equal(OpenID::Util.to_base64(@assoc.secret), rf['mac_key'])
    assert_equal("#{14 * 24 * 60 * 6}", rf['expires_in'])
    assert_nil(rf['session_type'])
    assert_nil(rf['enc_mac_key'])
    assert_nil(rf['dh_server_public'])
  end

end

class Counter
  
  attr_accessor :count

  def initialize
    @count = 0
  end

  def inc
    @count += 1
  end

end

class TestServer < Test::Unit::TestCase

  def setup
    @store = OpenID::MemoryStore.new
    @server = Server.new(@store)
  end

  def test_associate
    req = AssociateRequest.from_query({})
    res = @server.openid_associate(req)
    assert res.fields.has_key?('assoc_handle')
  end

  def test_check_auth
    req = CheckAuthRequest.new('arrrrg', '0x3999', [])
    res = @server.openid_check_authentication(req)
    assert res.fields.has_key?('is_valid')
  end

end

class TestSignatory < Test::Unit::TestCase

  def setup
    @store = OpenID::MemoryStore.new
    @signatory = Signatory.new(@store)
    @dumb_key = 'http://localhost/|dumb'
    @normal_key = 'http://localhost/|normal'    
  end

  def test_sign
    request = CheckIDRequest.new('checkid_setup','foo','bar','baz')
    assoc_handle = '{assoc}{lookatme}'
    @store.store_association(@normal_key,
                             OpenID::Association.from_expires_in(60,
                                                                 assoc_handle,
                                                                 'sekrit',
                                                                 'HMAC-SHA1'))
    request.assoc_handle = assoc_handle
    response = OpenIDResponse.new(request)
    response.fields = {
      'foo' => 'amsigned',
      'bar' => 'notsigned',
      'azu' => 'alsosigned'
    }
    response.signed = ['foo','azu']
    sresponse = @signatory.sign(response)
    
    assert_equal(assoc_handle, sresponse.fields['assoc_handle'])
    assert_equal('foo,azu', sresponse.fields['signed'])
    assert_not_nil(sresponse.fields['sig'])
  end

  def test_sign_dumb
    request = CheckIDRequest.new('checkid_setup','foo','bar','baz')
    request.assoc_handle = nil
    response = OpenIDResponse.new(request)
    response.fields = {
      'foo' => 'amsigned',
      'bar' => 'notsigned',
      'azu' => 'alsosigned'
    }
    response.signed = ['foo','azu']
    sresponse = @signatory.sign(response)
    assoc_handle = sresponse.fields['assoc_handle']
    assert_not_nil(assoc_handle)
    assoc = @signatory.get_association(assoc_handle, true)
    assert_not_nil(assoc)
    assert_equal('foo,azu', sresponse.fields['signed'])
    assert_not_nil(sresponse.fields['sig'])
  end
  
  def test_sign_expired
    request = CheckIDRequest.new('checkid_setup','foo','bar','baz')
    assoc_handle = '{assoc}{lookatme}'
    @store.store_association(@normal_key,
                             OpenID::Association.from_expires_in(-10,
                                                                 assoc_handle,
                                                                 'sekrit',
                                                                 'HMAC-SHA1'))
    assert_not_nil(@store.get_association(@normal_key, assoc_handle))
    
    request.assoc_handle = assoc_handle
    response = OpenIDResponse.new(request)
    response.fields = {
      'foo' => 'amsigned',
      'bar' => 'notsigned',
      'azu' => 'alsosigned'
    }
    response.signed = ['foo','azu']
    sresponse = @signatory.sign(response)
    
    new_assoc_handle = sresponse.fields['assoc_handle']
    assert_not_nil(new_assoc_handle)
    assert new_assoc_handle != assoc_handle
    
    assert_equal(assoc_handle, sresponse.fields['invalidate_handle'])
    assert_equal('foo,azu', sresponse.fields['signed'])
    assert_not_nil(sresponse.fields['sig'])

    assert_nil(@store.get_association(@normal_key, assoc_handle))
    assert_not_nil(@store.get_association(@dumb_key, new_assoc_handle))
    assert_nil(@store.get_association(@normal_key, new_assoc_handle))
  end
  
  def test_verify
    assoc_handle = '{vroom}{zoom}'
    assoc = OpenID::Association.from_expires_in(60, assoc_handle,
                                                'sekrit', 'HMAC-SHA1')
    
    @store.store_association(@dumb_key, assoc)
    
    signed_pairs = [['foo', 'bar'],['apple', 'orange']]
    
    sig = "Ylu0KcIR7PvNegB/K41KpnRgJl0="
    verified = @signatory.verify(assoc_handle, sig, signed_pairs)
    assert_not_nil(verified)
  end

  def test_verify_bad_sig
    assoc_handle = '{vroom}{zoom}'
    assoc = OpenID::Association.from_expires_in(60, assoc_handle,
                                                'sekrit', 'HMAC-SHA1')
    
    @store.store_association(@dumb_key, assoc)
    
    signed_pairs = [['foo', 'bar'],['apple', 'orange']]
    
    sig = "Ylu0KcIR7PvNegB/K41KpnRgXXX="
    verified = @signatory.verify(assoc_handle, sig, signed_pairs)
    assert(!verified)
  end

  def test_verify_bad_handle
    assoc_handle = '{vroom}{zoom}'
    signed_pairs = [['foo', 'bar'],['apple', 'orange']]
    
    sig = "Ylu0KcIR7PvNegB/K41KpnRgJl0="
    verified = @signatory.verify(assoc_handle, sig, signed_pairs)
    assert(!verified)
  end

  def make_assoc(dumb, lifetime=60)
    assoc_handle = '{bling}'
    assoc = OpenID::Association.from_expires_in(lifetime, assoc_handle,
                                                'sekrit', 'HMAC-SHA1')
    key = dumb ? @dumb_key : @normal_key
    @store.store_association(key, assoc)
    return assoc_handle                                                
  end
  
  def test_get_assoc
    assoc_handle = self.make_assoc(true)
    assoc = @signatory.get_association(assoc_handle, true)
    assert_not_nil(assoc)
    assert_equal(assoc_handle, assoc.handle)    
  end

  def test_get_assoc_expired
    assoc_handle = self.make_assoc(true, -10)
    assoc = @signatory.get_association(assoc_handle, true)
    assert_nil(assoc)
  end

  def test_get_assoc_invalid
    assoc_handle = 'no-such-handle'
    assoc = @signatory.get_association(assoc_handle, false)
    assert_nil(assoc)
  end

  def test_get_assoc_dumb_vs_normal
    assoc_handle = self.make_assoc(true)
    assoc = @signatory.get_association(assoc_handle, false)
    assert_nil(assoc)
  end

  def test_create_assoc
    assoc = @signatory.create_association(false)
    assoc2 = @signatory.get_association(assoc.handle, false)
    assert_not_nil(assoc2)
    assert_equal(assoc, assoc2)
  end
  
  def test_invalidate
    assoc_handle = '-squash-'
    assoc = OpenID::Association.from_expires_in(60, assoc_handle,
                                                'sekrit', 'HMAC-SHA1')
    @store.store_association(@dumb_key, assoc)
    assoc = @signatory.get_association(assoc_handle, true)
    assert_not_nil(assoc)

    assoc = @signatory.get_association(assoc_handle, true)
    assert_not_nil(assoc)

    @signatory.invalidate(assoc_handle, true)
    assoc = @signatory.get_association(assoc_handle, true)
    assert_nil(assoc)
  end

end

