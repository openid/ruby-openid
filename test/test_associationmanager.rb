require "openid/consumer/associationmanager"
require "openid/dh"
require "openid/util"
require "openid/cryptutil"
require "test/unit"

module OpenID
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
