require 'test/unit'
require 'fileutils'
require 'tmpdir'
require 'pathname'
require 'cgi'

require 'openid/server'
require 'openid/filestore'
require 'openid/dh'


class TestOpenIDServer < OpenID::OpenIDServer
  
  attr_reader :dumb_key
  public :associate, :get_auth_response, :check_authentication

end

module ServerTestCase 

  @@dir = Pathname.new(Dir.tmpdir).join('rubystoretest')

  def setup
    @sv_url = 'http://id.server.url/'
    @id_url = 'http://foo.com/'
    @rt_url = 'http://return.to/rt'
    @tr_url = 'http://return.to/'
    @store = OpenID::FilesystemStore.new(@@dir)
    @server = TestOpenIDServer.new(@sv_url, @store)
  end

  def teardown
    @store = nil
    FileUtils.rm_rf(@@dir)
  end

end

def parse_qsl(s)
  args = {}
  CGI::parse(s).each { |k,vals| args[k] = vals[0] }
  return args
end

class TestErrors < Test::Unit::TestCase
  include ServerTestCase

  def test_get_with_return_to
    args = {
      'openid.mode' => 'monkeydance',
      'openid.identity' => @id_url,
      'openid.return_to'=> @rt_url,
    }
    
    callback = lambda {|a,b| false}
    status, info = @server.get_openid_response('GET', args, callback)
   
    assert_equal(status, OpenID::REDIRECT)
    
    rt_base, result_args = info.split('?', 2)
    ra = parse_qsl(result_args)
    
    assert_equal(rt_base, @rt_url)
    assert_not_nil(ra['openid.mode'])
    assert_equal(ra['openid.mode'], 'error')
  end

  def test_get_bad_args
    args = {
      'openid.mode' => 'zebradance',
      'openid.identity'=> @id_url
    }

    status, info = @server.get_openid_response('GET', args,
                                               lambda {|a,b| false})
    assert_equal(status, OpenID::LOCAL_ERROR)
    assert_not_nil(info)
  end

  def test_no_args
    status, info = @server.get_openid_response('GET', {}, lambda {|a,b|false})
    assert_equal(status, OpenID::DO_ABOUT)
  end

  def test_post
    args = {
      'openid.mode' => 'pandadance',
      'openid.identity' => @id_url
    }
    status, info = @server.get_openid_response('POST', args,
                                               lambda {|a,b| false})
    assert_equal(status, OpenID::REMOTE_ERROR)
    result_args = OpenID::Util.parsekv(info)
    assert_not_nil(result_args['error'])
  end

end

class TestAssociate < Test::Unit::TestCase
  include ServerTestCase

  def test_associate_plain
    args = {}
    status, info = @server.associate(args)
    assert_equal(status, OpenID::REMOTE_OK)
    
    ra = OpenID::Util.parsekv(info)
    assert_equal(ra['assoc_type'], 'HMAC-SHA1')
    assert_equal(ra['session_type'], nil)
    assert_not_nil(ra['assoc_handle'])
    assert_not_nil(ra['mac_key'])
    assert_not_nil(ra['expires_in'])
    assert(ra['expires_in'].to_i > 0)
  end

  def test_associate_dh_defaults
    dh = OpenID::DiffieHellman.new
    cpub = OpenID::Util.num_to_base64(dh.public)
    args = {
      'openid.session_type' => 'DH-SHA1',
      'openid.dh_consumer_public' => cpub
    }
    status, info = @server.associate(args)
    ra = OpenID::Util.parsekv(info)
    
    assert_equal(status, OpenID::REMOTE_OK)
    assert_equal(ra['assoc_type'], 'HMAC-SHA1')
    assert_equal(ra['session_type'], 'DH-SHA1')
    assert_not_nil(ra['assoc_handle'])
    assert_not_nil(ra['dh_server_public'])
    assert_equal(ra['mac_key'], nil)
    assert_not_nil(ra['expires_in'])
    assert(ra['expires_in'].to_i > 0)
    assert_not_nil(ra['enc_mac_key'])

    enc_key = OpenID::Util.from_base64(ra['enc_mac_key'])
    spub = OpenID::Util.base64_to_num(ra['dh_server_public'])
    secret = dh.xor_secrect(spub, enc_key)
    assert_not_nil(secret)
  end

  def test_associate_dh_no_key
    args = {
      'openid.session_type' => 'DH-SHA1',
      # Oops, no key.
    }
    status, info = @server.associate(args)
    assert_equal(status, OpenID::REMOTE_ERROR)

    ra = OpenID::Util.parsekv(info)
    assert_not_nil(ra['error'])
  end

end

class TestGetAuthResponseDumb < Test::Unit::TestCase
  include ServerTestCase

  def test_checkid_immediate_failure
    args = {
      'openid.mode' => 'checkid_immediate',
      'openid.identity' => @id_url,
      'openid.return_to' => @rt_url
    }
    
    status, info = @server.get_auth_response(false, args)
    
    assert_equal(status, OpenID::REDIRECT)

    expected = @rt_url + '?openid.mode=id_res&openid.user_setup_url='
    eargs = {
      'openid.return_to' => @rt_url,      
      'openid.mode' => 'checkid_setup',
      'openid.identity' => @id_url,
    }
    expected += CGI::escape(@sv_url + '?' + OpenID::Util.urlencode(eargs))
    assert_equal(expected, info)
  end

  def test_checkid_immediate(mode='checkid_immediate')
    args = {
      'openid.mode' => mode,
      'openid.identity' => @id_url,
      'openid.return_to' => @rt_url,
    }

    status, info = @server.get_auth_response(true, args)

    assert_equal(status, OpenID::REDIRECT)

    rt_base, ra = info.split('?', 2)
    ra = parse_qsl(ra)

    assert_equal(rt_base, @rt_url)
    assert_equal(ra['openid.mode'], 'id_res')
    assert_equal(ra['openid.identity'], @id_url)
    assert_equal(ra['openid.return_to'], @rt_url)
    assert_equal(ra['openid.signed'], 'mode,identity,return_to')

    assoc = @store.get_association(@server.dumb_key,
                                   ra['openid.assoc_handle'])
    assert_not_nil(assoc)
    expect_sig = assoc.sign([['mode', 'id_res'],
                             ['identity', @id_url],
                             ['return_to', @rt_url]])
    sig = ra['openid.sig']
    sig = OpenID::Util.from_base64(sig)
    assert_equal(sig, expect_sig)
  end

  def test_checkid_setup
    test_checkid_immediate('checkid_setup')
  end

  def test_checkid_setup_need_auth
    args = {
      'openid.mode' => 'checkid_setup',
      'openid.identity' => @id_url,
      'openid.return_to' => @rt_url,
      'openid.trust_root' => @tr_url
    }

    status, info = @server.get_auth_response(false, args)

    assert_equal(status, OpenID::DO_AUTH)
    assert_equal(info.trust_root, @tr_url)
    assert_equal(info.identity_url, @id_url)
  end

  def test_checkid_setup_cancel
    args = {
      'openid.mode' => 'checkid_setup',
      'openid.identity' => @id_url,
      'openid.return_to' => @rt_url
    }

    status, info = @server.get_auth_response(false, args)

    assert_equal(status, OpenID::DO_AUTH)
    status, info = info.cancel
    
    assert_equal(status, OpenID::REDIRECT)

    rt_base, resultArgs = info.split('?', 2)
    ra = parse_qsl(resultArgs)
    assert_equal(rt_base, @rt_url)
    assert_equal(ra['openid.mode'], 'cancel')
  end

end

class TestCheckAuthentication < Test::Unit::TestCase
  include ServerTestCase

  def _dumb_request
    args = {
      'openid.mode' => 'checkid_immediate',
      'openid.identity' => @id_url,
      'openid.return_to' => @rt_url,
    }

    status, info = @server.get_auth_response(true, args)
    assert_equal(status, OpenID::REDIRECT)

    rt_base, resultArgs = info.split('?', 2)
    return parse_qsl(resultArgs)
  end

  def test_check_auth
    args = _dumb_request

    args['openid.mode'] = 'check_authentication'

    status, info = @server.check_authentication(args)
    assert_equal(status, OpenID::REMOTE_OK)

    resultArgs = OpenID::Util.parsekv(info)
    assert_equal(resultArgs['is_valid'], 'true')
  end

  def test_check_auth_fail_sig
    args = _dumb_request

    args['openid.mode'] = 'check_authentication'
    args['openid.sig'] = 'barf'

    status, info = @server.check_authentication(args)
    assert_equal(status, OpenID::REMOTE_OK)

    resultArgs = OpenID::Util.parsekv(info)
    assert_equal(resultArgs['is_valid'], 'false')
  end
  

  def test_check_auth_fail_handle
    args = _dumb_request

    args['openid.mode'] = 'check_authentication'
    args['openid.assoc_handle'] = 'barf'

    status, info = @server.check_authentication(args)
    assert_equal(status, OpenID::REMOTE_OK)

    resultArgs = OpenID::Util.parsekv(info)
    assert_equal(resultArgs['is_valid'], 'false')
  end
  
end
