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

  class TestCreateAssociationRequest < Test::Unit::TestCase
    def setup
      @server_url = 'http://invalid/'
      @assoc_manager = Consumer::AssociationManager.new(nil, @server_url)
      class << @assoc_manager
        def compatibility_mode=(val)
            @compatibility_mode = val
        end
      end
      @assoc_type = 'HMAC-SHA1'
    end

    def test_no_encryption_sends_type
      session_type = 'no-encryption'
      session, args = @assoc_manager.send(:create_associate_request,
                                          @assoc_type,
                                          session_type)

      assert(session.is_a?(Consumer::NoEncryptionSession))
      expected = Message.from_openid_args(
            {'ns' => OPENID2_NS,
             'session_type' => session_type,
             'mode' => 'associate',
             'assoc_type' => @assoc_type,
             })

      assert_equal(expected, args)
    end

    def test_no_encryption_compatibility
      @assoc_manager.compatibility_mode = true
      session_type = 'no-encryption'
      session, args = @assoc_manager.send(:create_associate_request,
                                          @assoc_type,
                                          session_type)

      assert(session.is_a?(Consumer::NoEncryptionSession))
      assert_equal(Message.from_openid_args({'mode' => 'associate',
                                              'assoc_type' => @assoc_type,
                                            }), args)
    end
    def test_dh_sha1_compatibility
      @assoc_manager.compatibility_mode = true
      session_type = 'DH-SHA1'
      session, args = @assoc_manager.send(:create_associate_request,
                                          @assoc_type,
                                          session_type)


      assert(session.is_a?(Consumer::DiffieHellmanSHA1Session))

      # This is a random base-64 value, so just check that it's
      # present.
      assert_not_nil(args.get_arg(OPENID1_NS, 'dh_consumer_public'))
      args.del_arg(OPENID1_NS, 'dh_consumer_public')

      # OK, session_type is set here and not for no-encryption
      # compatibility
      expected = Message.from_openid_args({'mode' => 'associate',
                                            'session_type' => 'DH-SHA1',
                                            'assoc_type' => @assoc_type,
                                          })
      assert_equal(expected, args)
    end
  end

  class TestAssociationManagerExpiresIn < Test::Unit::TestCase
    def expires_in_msg(val)
      msg = Message.from_openid_args({'expires_in' => val})
      Consumer::AssociationManager.extract_expires_in(msg)
    end

    def test_parse_fail
      ['',
       '-2',
       ' 1',
       ' ',
       '0x00',
       'foosball',
       '1\n',
       '100,000,000,000',
      ].each do |x|
        assert_raises(ProtocolError) {expires_in_msg(x)}
      end
    end

    def test_parse
      ['0',
       '1',
       '1000',
       '9999999',
       '01',
      ].each do |n|
        assert_equal(n.to_i, expires_in_msg(n))
      end
    end
  end

  class TestAssociationManagerCreateSession < Test::Unit::TestCase
    def test_invalid
      assert_raises(ArgumentError) {
        Consumer::AssociationManager.create_session('monkeys')
      }
    end
    def test_sha256
      sess = Consumer::AssociationManager.create_session('DH-SHA256')
      assert(sess.is_a?(Consumer::DiffieHellmanSHA256Session))
    end
  end
end
