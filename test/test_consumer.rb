require "openid/consumer"
require "test/unit"
require "openid/message"
require "openid/kvform"
require "openid/fetchers"

module OpenID
  class KVPostTestCase < Test::Unit::TestCase
    class MockResponse
      attr_reader :status, :body

      def initialize(status, body)
        @status = status
        @body = body
      end
    end

    def mk_resp(status, resp_hash)
      return MockResponse.new(status, Util.dict_to_kv(resp_hash))
    end

    def test_msg_from_http_resp_success
      resp = mk_resp(200, {'mode' => 'seitan'})
      msg = Message.from_http_response(resp, 'http://invalid/')
      assert_equal({'openid.mode' => 'seitan'}, msg.to_post_args)
    end

    def test_400
      args = {'error' => 'I ate too much cheese',
        'error_code' => 'sadness'}
      resp = mk_resp(400, args)
      begin
        val = Message.from_http_response(resp, 'http://invalid/')
      rescue ServerError => why
        assert_equal(why.error_text, 'I ate too much cheese')
        assert_equal(why.error_code, 'sadness')
        assert_equal(why.message.to_args, args)
      else
        fail("Expected exception. Got: #{val}")
      end
    end

    def test_500
      args = {'error' => 'I ate too much cheese',
        'error_code' => 'sadness'}
      resp = mk_resp(500, args)
      assert_raises(StandardError) {
        Message.from_http_response(resp, 'http://invalid')
      }
    end

    def make_kv_post_with_response(status, args)
      mock_fetcher = Class.new do
        attr_accessor :resp

        def fetch(url, body, xxx, yyy)
          @resp
          # XXX: check for the args we expect
        end
      end
      fetcher = mock_fetcher.new
      fetcher.resp = mk_resp(status, args)

      old_fetcher = OpenID.get_current_fetcher
      begin
        OpenID.set_default_fetcher(fetcher)
        OpenID.make_kv_post(Message.from_openid_args(args), 'http://invalid/')
      ensure
        OpenID.set_default_fetcher(old_fetcher)
      end
    end

    def test_make_kv_post
      assert_raises(StandardError) {
        make_kv_post_with_response(500, {})
      }
    end
  end

  class DHAssocSessionTest < Test::Unit::TestCase
    def test_sha1_get_request
      # Initialized without an explicit DH gets defaults
      sess = Consumer::DiffieHellmanSHA1Session.new
      assert_equal(['dh_consumer_public'], sess.get_request.keys)
      assert_nothing_raised do
        Util::from_base64(sess.get_request['dh_consumer_public'])
      end
    end

    def test_sha1_get_request_custom_dh
      dh = DiffieHellman.new(1299721, 2)
      sess = Consumer::DiffieHellmanSHA1Session.new(dh)
      req = sess.get_request
      assert_equal(['dh_consumer_public', 'dh_modulus', 'dh_gen'].sort,
                   req.keys.sort)
      assert_equal(dh.modulus, CryptUtil.base64_to_num(req['dh_modulus']))
      assert_equal(dh.generator, CryptUtil.base64_to_num(req['dh_gen']))
      assert_nothing_raised do
        Util::from_base64(req['dh_consumer_public'])
      end
    end
  end

  module TestDiffieHellmanResponseParametersMixin
    def setup
      session_cls = self.class.session_cls

      # Pre-compute DH with small prime so tests run quickly.
      @server_dh = DiffieHellman.new(100389557, 2)
      @consumer_dh = DiffieHellman.new(100389557, 2)

      # base64(btwoc(g ^ xb mod p))
      @dh_server_public = CryptUtil.num_to_base64(@server_dh.public)

      @secret = CryptUtil.random_string(session_cls.secret_size)

      enc_mac_key_unencoded =
        @server_dh.xor_secret(session_cls.hashfunc,
                              @consumer_dh.public,
                              @secret)

      @enc_mac_key = Util.to_base64(enc_mac_key_unencoded)

      @consumer_session = session_cls.new(@consumer_dh)

      @msg = Message.new(self.class.message_namespace)
    end

    def test_extract_secret
      @msg.set_arg(OPENID_NS, 'dh_server_public', @dh_server_public)
      @msg.set_arg(OPENID_NS, 'enc_mac_key', @enc_mac_key)

      extracted = @consumer_session.extract_secret(@msg)
      assert_equal(extracted, @secret)
    end

    def test_absent_serve_public
      @msg.set_arg(OPENID_NS, 'enc_mac_key', @enc_mac_key)

      assert_raises(IndexError) {
        @consumer_session.extract_secret(@msg)
      }
    end

    def test_absent_mac_key
      @msg.set_arg(OPENID_NS, 'dh_server_public', @dh_server_public)

      assert_raises(IndexError) {
        @consumer_session.extract_secret(@msg)
      }
    end

    def test_invalid_base64_public
      @msg.set_arg(OPENID_NS, 'dh_server_public', 'n o t b a s e 6 4.')
      @msg.set_arg(OPENID_NS, 'enc_mac_key', @enc_mac_key)

      assert_raises(ArgumentError) {
        @consumer_session.extract_secret(@msg)
      }
    end

    def test_invalid_base64_mac_key
      @msg.set_arg(OPENID_NS, 'dh_server_public', @dh_server_public)
      @msg.set_arg(OPENID_NS, 'enc_mac_key', 'n o t base 64')

      assert_raises(ArgumentError) {
        @consumer_session.extract_secret(@msg)
      }
    end
  end

  class TestConsumerOpenID1DHSHA1 < Test::Unit::TestCase
    include TestDiffieHellmanResponseParametersMixin
    class << self
      attr_reader :session_cls, :message_namespace
    end

    @session_cls = Consumer::DiffieHellmanSHA1Session
    @message_namespace = OPENID1_NS
  end

  class TestConsumerOpenID2DHSHA1 < Test::Unit::TestCase
    include TestDiffieHellmanResponseParametersMixin
    class << self
      attr_reader :session_cls, :message_namespace
    end

    @session_cls = Consumer::DiffieHellmanSHA1Session
    @message_namespace = OPENID2_NS
  end

  class TestConsumerOpenID2DHSHA256 < Test::Unit::TestCase
    include TestDiffieHellmanResponseParametersMixin
    class << self
      attr_reader :session_cls, :message_namespace
    end

    @session_cls = Consumer::DiffieHellmanSHA256Session
    @message_namespace = OPENID2_NS
  end

  class TestConsumerNoEncryptionSession < Test::Unit::TestCase
    def setup
      @sess = Consumer::NoEncryptionSession.new
    end

    def test_empty_request
      assert_equal(@sess.get_request, {})
    end

    def test_get_secret
      secret = 'shhh!' * 4
      mac_key = Util.to_base64(secret)
      msg = Message.from_openid_args({'mac_key' => mac_key})
      assert_equal(secret, @sess.extract_secret(msg))
    end
  end
end
