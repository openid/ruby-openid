require 'cgi'
require 'uri'
require 'test/unit'

require 'openid/util'
require 'openid/dh'
require 'openid/stores'
require 'openid/consumer'
require 'openid/service'
require 'openid/association'

ASSOCS = [
          ['another 20-byte key.', 'Snarky'],
          ["\x00" * 20, 'Zeros']
         ]

HTTP_SERVER_URL = 'http://server.example.com/'
HTTPS_SERVER_URL = 'https://server.example.com/'
CONSUMER_URL = 'http://consumer.example.com/'


# extract a hash from an application/x-www-form-urlencoded string
def parse_query(qs)
  query = {}
  CGI::parse(qs).each {|k,v| query[k] = v[0]}
  return query
end

# do the server side associate using the given secret and handle
def associate(qs, assoc_secret, assoc_handle)
  q = parse_query(qs)
  raise ArgumentError unless q['openid.mode'] == 'associate' 
  raise ArgumentError unless q['openid.assoc_type'] == 'HMAC-SHA1' 

  if q['openid.session_type'] == 'DH-SHA1'
    raise ArgumentError unless [4,6].member?(q.length)
    d = OpenID::DiffieHellman.from_base64(q['openid.dh_modulus'],
                                          q['openid.dh_gen'])
    composite = OpenID::Util.base64_to_num(q['openid.dh_consumer_public'])
    enc_mac_key = OpenID::Util.to_base64(d.xor_secrect(composite,
                                                       assoc_secret))
    reply = {
      'assoc_type' => 'HMAC-SHA1',
      'assoc_handle' => assoc_handle,
      'expires_in' => '600',
      'session_type' => 'DH-SHA1',
      'dh_server_public' => OpenID::Util.num_to_base64(d.public),
      'enc_mac_key' => enc_mac_key
    }
  else
    # dumb mode
    raise ArgumentError unless q.length == 2
    mac_key = OpenID::Util.to_base64(assoc_secret)
    reply = {
      'assoc_type' => 'HMAC-SHA1',
      'assoc_handle' => assoc_handle,
      'expires_in' => '600',
      'mac_key' => mac_key
    }
  end

  return OpenID::Util.kvform(reply)
end


class TestFetcher
  
  attr_accessor :get_responses, :assoc_secret, :assoc_handle, :num_assocs

  def initialize(assoc_secret, assoc_handle)
    @get_responses = {}
    @assoc_secret = assoc_secret
    @assoc_handle = assoc_handle
    @num_assocs = 0
  end
  
  def response(url, status, body)
    return [url, body]
  end

  def fetch(url, body=nil, headers=nil)
    if body.nil?
      return @get_responses[url] if @get_responses.has_key?(url)

    else
      if body.include?('openid.mode=associate')
        response = associate(body, @assoc_secret, @assoc_handle)
        @num_assocs += 1
        return [url, response]
      end
    end
    
    return [url, 'not found']
  end

  def get(url)
    return self.fetch(url)
  end

  def post(url, body)
    return self.fetch(url, body)
  end

end

class SuccessFlowTest < Test::Unit::TestCase

  def _test_success(service, immediate=false)
    store = OpenID::MemoryStore.new
    mode = immediate ? 'checkid_immediate' : 'checkid_setup'

    assoc_secret, assoc_handle = ASSOCS[0]
    fetcher = TestFetcher.new(assoc_secret, assoc_handle)
    
    run = Proc.new {
      trust_root = CONSUMER_URL
      return_to = CONSUMER_URL
      session = {}
      
      consumer = OpenID::Consumer.new(session, store, fetcher)
      req = consumer.begin_without_discovery(service)

      # need to extract the return_to url
      
      return_to = req.return_to(return_to)

      assert_equal(OpenID::SUCCESS, req.status)

      redirect_url = req.redirect_url(trust_root, return_to, immediate)
      assert redirect_url.starts_with?(service.server_url)

      # make sure the query in the redirect URL is what we want
      q = parse_query(URI.parse(redirect_url).query)

      assert_equal(mode, q['openid.mode'])
      assert_equal(service.server_id, q['openid.identity'])
      assert_equal(trust_root, q['openid.trust_root'])
      assert_equal(fetcher.assoc_handle, q['openid.assoc_handle'])

      # make sure the return_to has the nonce in it
      return_to_query = parse_query(URI.parse(q['openid.return_to']).query)
      assert return_to_query.has_key?('nonce')

      # build a fake response from the OpenID server
      query = {
        'openid.mode' => 'id_res',
        'openid.return_to' => 'return_to',
        'openid.identity' => service.server_id,
        'openid.assoc_handle' => fetcher.assoc_handle,
        'nonce' => return_to_query['nonce']
      }
      
      # sign the fake response with our assoc
      assoc = store.get_association(service.server_url, fetcher.assoc_handle)
      assoc.add_signature(['mode','return_to','identity'], query)
      
      # complete the auth
      resp = consumer.complete(query)

      if resp.status == OpenID::FAILURE
        p 'Failure Message', resp.msg
      end

      # we're testing success here, so make sure we have a success response
      assert_equal(OpenID::SUCCESS, resp.status)
      
      # make sure we've got the right identity url
      assert_equal(service.consumer_id, resp.identity_url)
    }

    assert_equal(0, fetcher.num_assocs)
    run.call
    assert_equal(1, fetcher.num_assocs)
    
    # make sure we use the same association
    run.call
    assert_equal(1, fetcher.num_assocs)

    # another assoc is created if we remove the existing one
    store.remove_association(service.server_url, fetcher.assoc_handle)
    run.call
    assert_equal(2, fetcher.num_assocs)
    run.call
    assert_equal(2, fetcher.num_assocs)
  end

  def test_no_delegate
    service = OpenID::FakeOpenIDServiceEndpoint.new(
                      'http://example.com/user.html',
                      'http://example.com/user.html',
                       HTTP_SERVER_URL)
    self._test_success(service)    
  end

  def test_nodelegate_immediate
    service = OpenID::FakeOpenIDServiceEndpoint.new(
                      'http://example.com/user.html',
                      'http://example.com/user.html',
                       HTTP_SERVER_URL)
    self._test_success(service, true)    
  end

  def test_delegate
    s = OpenID::FakeOpenIDServiceEndpoint.new(
                      'http://example.com/user.html',
                      'http://server.com/user.html',
                      HTTP_SERVER_URL)
    self._test_success(s)
  end

  def test_delegate_immediate
    s = OpenID::FakeOpenIDServiceEndpoint.new(
                      'http://example.com/user.html',
                      'http://server.com/user.html',
                      HTTP_SERVER_URL)
    self._test_success(s, true)
  end

  def test_https
    service = OpenID::FakeOpenIDServiceEndpoint.new(
                      'http://example.com/user.html',
                      'http://example.com/user.html',
                       HTTPS_SERVER_URL)
    self._test_success(service)    
  end

end


class TestIdRes < Test::Unit::TestCase
  
  def test_setup_needed
    store = OpenID::MemoryStore.new
    consumer = OpenID::GenericConsumer.new(store)
    return_to = "nonny"
    server_id = "sirod"
    server_url = "serlie"
    consumer_id = "consu"
    setup_url = "http://example.com/setup-here"
    
    query = {
      'openid.mode' => 'id_res',
      'openid.user_setup_url' => setup_url
    }

    nonce = consumer.create_nonce
    ret = consumer.do_id_res(nonce, consumer_id, server_id, server_url, query)

    assert_equal(OpenID::SETUP_NEEDED, ret.status)
    assert_equal(setup_url, ret.setup_url)    
  end

end


class CheckAuthHappened < Exception; end

class CheckAuthDetectingConsumer < OpenID::GenericConsumer
  
  def check_auth(nonce, query, server_url)
    raise CheckAuthHappened
  end

end

class TestCheckAuth < Test::Unit::TestCase

  def setup
    @store = OpenID::MemoryStore.new
    @consumer = CheckAuthDetectingConsumer.new(@store)
    @return_to = "nonny"
    @server_id = "sirod"
    @server_url = "http://server.com/url"
    @consumer_id = "consu"
    @nonce = @consumer.create_nonce
    @setup_url = "http://example.com/setup-here"
  end


  def _do_id_res(query)
    return @consumer.do_id_res(@nonce, @consumer_id, @server_id, @server_url,
                               query)
  end

  def test_chech_auth_triggered
    query = {
      'openid.return_to' => @return_to,
      'openid.identity' => @server_id,
      'openid.assoc_handle' => 'not_found'
    }
    begin
      self._do_id_res(query)
    rescue CheckAuthHappened
      assert true
    else
      raise 'CheckAuthDidntHappen'
    end
  end

  def test_check_auth_triggered_with_assoc
    issued = Time.now.to_i
    lifetime = 1000
    assoc = OpenID::Association.new('handle',
                                    'secret',
                                    issued,
                                    lifetime, 'HMAC-SHA1')

    @store.store_association(@server_url, assoc)

    query = {
      'openid.return_to' => @return_to,
      'openid.identity' => @server_id,
      'openid.assoc_handle' => 'bad_assoc_handle_for_assoc!'
    }

    begin
      result = self._do_id_res(query)
    rescue CheckAuthHappened
      assert true
    else
      raise ArgumentError.new(result.msg)
    end
  end

  def test_expired_assoc
    issued = Time.now.to_i - 10
    lifetime = 0
    handle = 'handle'
    assoc = OpenID::Association.new(handle, 'secret', issued, lifetime,
                                    'HMAC-SHA1')
    assert assoc.expires_in <= 0
    @store.store_association(@server_url, assoc)

    query = {
      'openid.return_to' => @return_to,
      'openid.identity' => @server_id,
      'openid.assoc_handle' => handle
    }

    info = self._do_id_res(query)
    assert_equal(OpenID::FAILURE, info.status)
    assert_equal(@consumer_id, info.identity_url)
  end

  def test_newer_assoc   
    lifetime = 1000
    good_issued = Time.now.to_i - 10
    good_handle = 'handle'
    good_assoc = OpenID::Association.new(good_handle, 'secret',
                                         good_issued, lifetime, 'HMAC-SHA1')
    @store.store_association(@server_url, good_assoc)
    
    bad_issued = Time.now.to_i - 5
    bad_handle = 'handle2'
    bad_assoc = OpenID::Association.new(bad_handle, 'secret',
                                        bad_issued, lifetime, 'HMAC-SHA1')
    @store.store_association(@server_url, bad_assoc)
    
    query = {
      'openid.return_to' => @return_to,
      'openid.identity' => @server_id,
      'openid.assoc_handle' => good_handle
    }

    good_assoc.add_signature(['return_to','identity'], query)
    info = self._do_id_res(query)

    if info.status != OpenID::SUCCESS
      p 'Failure Message', info.msg
    end

    assert_equal(OpenID::SUCCESS, info.status)
    assert_equal(@consumer_id, info.identity_url)    
  end

end
