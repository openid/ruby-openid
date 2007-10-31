require "openid/consumer/associationmanager"
require "openid/association"
require "openid/dh"
require "openid/util"
require "openid/cryptutil"
require "openid/message"
require "test/unit"
require "util"

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

###################################33

  module NegotiationTestMixin
    include TestUtil
    def mk_message(args)
      args['ns'] = @openid_ns
      Message.from_openid_args(args)
    end

    def call_negotiate(responses, negotiator=nil)
      store = nil
      compat = self.class::Compat
      assoc_manager = Consumer::AssociationManager.new(store, @server_url,
                                                       compat, negotiator)
      class << assoc_manager
        attr_accessor :responses

        def request_association(assoc_type, session_type)
          m = @responses.shift
          if m.is_a?(Message)
            raise ServerError.from_message(m)
          else
            return m
          end
        end
      end
      assoc_manager.responses = responses
      assoc_manager.negotiate_association
    end
  end

  # Test the session type negotiation behavior of an OpenID 2
  # consumer.
  class TestOpenID2SessionNegotiation < Test::Unit::TestCase
    include NegotiationTestMixin

    Compat = false

    def setup
      @server_url = 'http://invalid/'
      @openid_ns = OPENID2_NS
    end

    # Test the case where the response to an associate request is a
    # server error or is otherwise undecipherable.
    def test_bad_response
      assert_log_matches('Server error when requesting an association') {
        assert_equal(call_negotiate([mk_message({})]), nil)
      }
    end

    # Test the case where the association type (assoc_type) returned
    # in an unsupported-type response is absent.
    def test_empty_assoc_type
      msg = mk_message({'error' => 'Unsupported type',
                              'error_code' => 'unsupported-type',
                              'session_type' => 'new-session-type',
                            })

      assert_log_matches('Unsupported association type',
                         "Server #{@server_url} responded with unsupported "\
                         "association session but did not supply a fallback."
                         ) {
        assert_equal(call_negotiate([msg]), nil)
      }

    end

    # Test the case where the session type (session_type) returned
    # in an unsupported-type response is absent.
    def test_empty_session_type
      msg = mk_message({'error' => 'Unsupported type',
                              'error_code' => 'unsupported-type',
                              'assoc_type' => 'new-assoc-type',
                            })

      assert_log_matches('Unsupported association type',
                         "Server #{@server_url} responded with unsupported "\
                         "association session but did not supply a fallback."
                         ) {
        assert_equal(call_negotiate([msg]), nil)
      }
    end

    # Test the case where an unsupported-type response specifies a
    # preferred (assoc_type, session_type) combination that is not
    # allowed by the consumer's SessionNegotiator.
    def test_not_allowed
      negotiator = AssociationNegotiator.new([])
      negotiator.instance_eval{
        @allowed_types = [['assoc_bogus', 'session_bogus']]
      }
      msg = mk_message({'error' => 'Unsupported type',
                              'error_code' => 'unsupported-type',
                              'assoc_type' => 'not-allowed',
                              'session_type' => 'not-allowed',
                            })

      assert_log_matches('Unsupported association type',
                         'Server sent unsupported session/association type:') {
        assert_equal(call_negotiate([msg], negotiator), nil)
      }
    end

    # Test the case where an unsupported-type response triggers a
    # retry to get an association with the new preferred type.
    def test_unsupported_with_retry
      msg = mk_message({'error' => 'Unsupported type',
                              'error_code' => 'unsupported-type',
                              'assoc_type' => 'HMAC-SHA1',
                              'session_type' => 'DH-SHA1',
                            })

      assoc = Association.new('handle', 'secret', 'issued', 10000, 'HMAC-SHA1')

      assert_log_matches('Unsupported association type') {
        assert_equal(assoc, call_negotiate([msg, assoc]))
      }
    end

    # Test the case where an unsupported-typ response triggers a
    # retry, but the retry fails and nil is returned instead.
    def test_unsupported_with_retry_and_fail
      msg = mk_message({'error' => 'Unsupported type',
                              'error_code' => 'unsupported-type',
                              'assoc_type' => 'HMAC-SHA1',
                              'session_type' => 'DH-SHA1',
                            })

      assert_log_matches('Unsupported association type',
                         "Server #{@server_url} refused") {
        assert_equal(call_negotiate([msg, msg]), nil)
      }
    end

    # Test the valid case, wherein an association is returned on the
    # first attempt to get one.
    def test_valid
      assoc = Association.new('handle', 'secret', 'issued', 10000, 'HMAC-SHA1')

      assert_log_matches() {
        assert_equal(call_negotiate([assoc]), assoc)
      }
    end
  end


  # Tests for the OpenID 1 consumer association session behavior.  See
  # the docs for TestOpenID2SessionNegotiation.  Notice that this
  # class is not a subclass of the OpenID 2 tests.  Instead, it uses
  # many of the same inputs but inspects the log messages logged with
  # oidutil.log.  See the calls to self.failUnlessLogMatches.  Some of
  # these tests pass openid2-style messages to the openid 1
  # association processing logic to be sure it ignores the extra data.
  class TestOpenID1SessionNegotiation < Test::Unit::TestCase
    include NegotiationTestMixin

    Compat = true

    def setup
      @server_url = 'http://invalid/'
      @openid_ns = OPENID1_NS
    end

    def test_bad_response
      assert_log_matches('Server error when requesting an association') {
        response = call_negotiate([mk_message({})])
        assert_equal(nil, response)
      }
    end

    def test_empty_assoc_type
      msg = mk_message({'error' => 'Unsupported type',
                         'error_code' => 'unsupported-type',
                         'session_type' => 'new-session-type',
                       })

      assert_log_matches('Server error when requesting an association') {
        response = call_negotiate([msg])
        assert_equal(nil, response)
      }
    end

    def test_empty_session_type
      msg = mk_message({'error' => 'Unsupported type',
                         'error_code' => 'unsupported-type',
                         'assoc_type' => 'new-assoc-type',
                       })

      assert_log_matches('Server error when requesting an association') {
        response = call_negotiate([msg])
        assert_equal(nil, response)
      }
    end

    def test_not_allowed
      negotiator = AssociationNegotiator.new([])
      negotiator.instance_eval{
        @allowed_types = [['assoc_bogus', 'session_bogus']]
      }

      msg = mk_message({'error' => 'Unsupported type',
                         'error_code' => 'unsupported-type',
                         'assoc_type' => 'not-allowed',
                         'session_type' => 'not-allowed',
                       })

      assert_log_matches('Server error when requesting an association') {
        response = call_negotiate([msg])
        assert_equal(nil, response)
      }
    end

    def test_unsupported_with_retry
      msg = mk_message({'error' => 'Unsupported type',
                         'error_code' => 'unsupported-type',
                         'assoc_type' => 'HMAC-SHA1',
                         'session_type' => 'DH-SHA1',
                       })

      assoc = Association.new('handle', 'secret', 'issued', 10000, 'HMAC-SHA1')


      assert_log_matches('Server error when requesting an association') {
        response = call_negotiate([msg, assoc])
        assert_equal(nil, response)
      }
    end

    def test_valid
      assoc = Association.new('handle', 'secret', 'issued', 10000, 'HMAC-SHA1')
      assert_log_matches() {
        response = call_negotiate([assoc])
        assert_equal(assoc, response)
      }
    end
  end

end
