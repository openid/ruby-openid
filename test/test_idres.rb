require "testutil"
require "util"
require "test/unit"
require "openid/consumer/idres"
require "openid/protocolerror"
require "openid/store/memstore"

module OpenID
  class Consumer
    class IdResHandler
      class CheckForFieldsTest < Test::Unit::TestCase
        include ProtocolErrorMixin

        BASE_FIELDS = ['return_to', 'assoc_handle', 'sig', 'signed']
        OPENID2_FIELDS = BASE_FIELDS + ['op_endpoint']
        OPENID1_FIELDS = BASE_FIELDS + ['identity']

        OPENID1_SIGNED = ['return_to', 'identity']
        OPENID2_SIGNED =
          OPENID1_SIGNED + ['response_nonce', 'claimed_id', 'assoc_handle']

        def mkMsg(ns, fields, signed_fields)
          msg = Message.new(ns)
          fields.each do |field|
            msg.set_arg(OPENID_NS, field, "don't care")
          end
          if fields.member?('signed')
            msg.set_arg(OPENID_NS, 'signed', signed_fields.join(','))
          end
          msg
        end

        1.times do # so as not to bleed into the outer namespace
          n = 0
          [[],
           ['foo'],
           ['bar', 'baz'],
          ].each do |signed_fields|
            test = lambda do
              msg = mkMsg(OPENID2_NS, OPENID2_FIELDS, signed_fields)
              idres = IdResHandler.new(msg)
              assert_equal(signed_fields, idres.send(:signed_list))
              # Do it again to make sure logic for caching is correct
              assert_equal(signed_fields, idres.send(:signed_list))
            end
            define_method("test_signed_list_#{n += 1}", test)
          end
        end

        # test all missing fields for OpenID 1 and 2
        1.times do
          [["openid1", OPENID1_NS, OPENID1_FIELDS],
           ["openid2", OPENID2_NS, OPENID2_FIELDS],
          ].each do |ver, ns, all_fields|
            all_fields.each do |field|
              test = lambda do
                fields = all_fields.dup
                fields.delete(field)
                msg = mkMsg(ns, fields, [])
                idres = IdResHandler.new(msg)
                assert_protocol_error("Missing required field #{field}") {
                  idres.send(:check_for_fields)
                }
              end
              define_method("test_#{ver}_check_missing_#{field}", test)
            end
          end
        end

        # Test all missing signed for OpenID 1 and 2
        1.times do
          [["openid1", OPENID1_NS, OPENID1_FIELDS, OPENID1_SIGNED],
           ["openid2", OPENID2_NS, OPENID2_FIELDS, OPENID2_SIGNED],
          ].each do |ver, ns, all_fields, signed_fields|
            signed_fields.each do |signed_field|
              test = lambda do
                fields = signed_fields.dup
                fields.delete(signed_field)
                msg = mkMsg(ns, all_fields, fields)
                # Make sure the signed field is actually in the request
                msg.set_arg(OPENID_NS, signed_field, "don't care")
                idres = IdResHandler.new(msg)
                assert_protocol_error("#{signed_field.inspect} not signed") {
                  idres.send(:check_for_fields)
                }
              end
              define_method("test_#{ver}_check_missing_signed_#{signed_field}", test)
            end
          end
        end

        def test_no_signed_list
          msg = Message.new(OPENID2_NS)
          idres = IdResHandler.new(msg)
          assert_protocol_error("Response missing signed") {
            idres.send(:signed_list)
          }
        end

        def test_success_openid1
          msg = mkMsg(OPENID1_NS, OPENID1_FIELDS, OPENID1_SIGNED)
          idres = IdResHandler.new(msg)
          assert_nothing_raised {
            idres.send(:check_for_fields)
          }
        end
      end

      class ReturnToArgsTest < Test::Unit::TestCase
        include OpenID::ProtocolErrorMixin

        def check_return_to_args(query)
          idres = IdResHandler.new(Message.from_post_args(query))
          class << idres
            def verify_return_to_base(unused)
            end
          end
          idres.send(:verify_return_to)
        end

        def assert_bad_args(msg, query)
          assert_protocol_error(msg) {
            check_return_to_args(query)
          }
        end

        def test_return_to_args_okay
          assert_nothing_raised {
            check_return_to_args({
              'openid.mode' => 'id_res',
              'openid.return_to' => 'http://example.com/?foo=bar',
              'foo' => 'bar',
              })
          }
        end

        def test_unexpected_arg_okay
          assert_bad_args("Parameter foo does", {
              'openid.mode' => 'id_res',
              'openid.return_to' => 'http://example.com/',
              'foo' => 'bar',
              })
        end

        def test_return_to_mismatch
          assert_bad_args('Message missing ret', {
            'openid.mode' => 'id_res',
            'openid.return_to' => 'http://example.com/?foo=bar',
            })

          assert_bad_args('Parameter foo val', {
            'openid.mode' => 'id_res',
            'openid.return_to' => 'http://example.com/?foo=bar',
            'foo' => 'foos',
            })
        end
      end

      class ReturnToVerifyTest < Test::Unit::TestCase
        def test_bad_return_to
          return_to = "http://some.url/path?foo=bar"
          
          m = Message.new(OPENID1_NS)
          m.set_arg(OPENID_NS, 'mode', 'cancel')
          m.set_arg(BARE_NS, 'foo', 'bar')
          
          # Scheme, authority, and path differences are checked by
          # IdResHandler.verify_return_to_base.  Query args checked by
          # IdResHandler.verify_return_to_args.
          [
            # Scheme only
            "https://some.url/path?foo=bar",
            # Authority only
            "http://some.url.invalid/path?foo=bar",
            # Path only
            "http://some.url/path_extra?foo=bar",
            # Query args differ
            "http://some.url/path?foo=bar2",
            "http://some.url/path?foo2=bar",
            ].each do |bad|
              m.set_arg(OPENID_NS, 'return_to', bad)
              idres = IdResHandler.new(m, nil, nil, return_to)
              assert_raises(ProtocolError) {
                idres.send(:verify_return_to)
              }
          end
        end

        def test_good_return_to
          base = 'http://example.janrain.com/path'
          [ [base, {}],
            [base + "?another=arg", {'another' => 'arg'}],
            [base + "?another=arg#frag", {'another' => 'arg'}],
          ].each do |return_to, args|
            args['openid.return_to'] = return_to
            msg = Message.from_post_args(args)
            idres = IdResHandler.new(msg, nil, nil, base)
            assert_nothing_raised {
              idres.send(:verify_return_to)
            }
          end
        end
      end

      GOODSIG = '[A Good Signature]'

      class GoodAssoc
        attr_accessor :handle, :expires_in

        def initialize(handle='-blah-')
          @handle = handle
          @expires_in = 3600
        end

        def check_message_signature(msg)
          msg.get_arg(OPENID_NS, 'sig') == GOODSIG
        end
      end

      class DummyEndpoint
        attr_accessor :server_url
        def initialize(server_url)
          @server_url = server_url
        end
      end

      class CheckSigTest < Test::Unit::TestCase
        include ProtocolErrorMixin
        include TestUtil

        def setup
          @assoc = GoodAssoc.new('{not_dumb}')
          @store = MemoryStore.new
          @server_url = 'http://server.url/'
          @endpoint = DummyEndpoint.new(@server_url)
          @store.store_association(@server_url, @assoc)

          @message = Message.from_post_args({
              'openid.mode' => 'id_res',
              'openid.identity' => '=example',
              'openid.sig' => GOODSIG,
              'openid.assoc_handle' => @assoc.handle,
              'openid.signed' => 'mode,identity,assoc_handle,signed',
              'frobboz' => 'banzit',
              })
        end

        def call_idres_method(method_name)
          idres = IdResHandler.new(@message, @store, @endpoint)
          idres.extend(InstanceDefExtension)
          yield idres
          idres.send(method_name)
        end

        def call_check_sig(&proc)
          call_idres_method(:check_signature, &proc)
        end

        def no_check_auth(idres)
          idres.instance_def(:check_auth) { fail "Called check_auth" }
        end

        def test_sign_good
          assert_nothing_raised {
            call_check_sig(&method(:no_check_auth))
          }
        end

        def test_bad_sig
          @message.set_arg(OPENID_NS, 'sig', 'bad sig!')
          assert_protocol_error('Bad signature') {
            call_check_sig(&method(:no_check_auth))
          }
        end

        def test_check_auth_ok
          @message.set_arg(OPENID_NS, 'assoc_handle', 'dumb-handle')
          check_auth_called = false
          call_check_sig do |idres|
            idres.instance_def(:check_auth) do
              check_auth_called = true
            end
          end
          assert(check_auth_called)
        end

        def test_check_auth_ok_no_store
          @store = nil
          check_auth_called = false
          call_check_sig do |idres|
            idres.instance_def(:check_auth) do
              check_auth_called = true
            end
          end
          assert(check_auth_called)
        end

        def test_expired_assoc
          @assoc.expires_in = -1
          @store.store_association(@server_url, @assoc)
          assert_protocol_error('Association with') {
            call_check_sig(&method(:no_check_auth))
          }
        end

        def call_check_auth(&proc)
          assert_log_matches("Using 'check_authentication'") {
            call_idres_method(:check_auth, &proc)
          }
        end

        def test_check_auth_create_fail
          assert_protocol_error("Could not generate") {
            call_check_auth do |idres|
              idres.instance_def(:create_check_auth_request) do
                raise Message::KeyNotFound, "Testing"
              end
            end
          }
        end

        def test_kv_server_error
          OpenID.extend(OverrideMethodMixin)
          send_error = lambda do |req, server_url|
            msg = Message.new(OPENID2_NS)
            raise ServerError.from_message(msg), 'For you!'
          end
            
          OpenID.with_method_overridden(:make_kv_post, send_error) do
            assert_protocol_error("Error from") {
              call_check_auth do |idres|
                idres.instance_def(:create_check_auth_request) { nil }
              end
            }
          end
        end

        def test_check_auth_okay
          OpenID.extend(OverrideMethodMixin)
          me = self
          send_resp = Proc.new do |req, server_url|
            me.assert_equal(:req, req)
            :expected_response
          end
            
          OpenID.with_method_overridden(:make_kv_post, send_resp) do
            final_resp = call_check_auth do |idres|
              idres.instance_def(:create_check_auth_request) {
                :req
              }
              idres.instance_def(:process_check_auth_response) do |resp|
                me.assert_equal(:expected_response, resp)
              end
            end
          end
        end

        def test_check_auth_process_fail
          OpenID.extend(OverrideMethodMixin)
          me = self
          send_resp = Proc.new do |req, server_url|
            me.assert_equal(:req, req)
            :expected_response
          end

          OpenID.with_method_overridden(:make_kv_post, send_resp) do
            assert_protocol_error("Testing") do
              final_resp = call_check_auth do |idres|
                idres.instance_def(:create_check_auth_request) { :req }
                idres.instance_def(:process_check_auth_response) do |resp|
                  me.assert_equal(:expected_response, resp)
                  raise ProtocolError, "Testing"
                end
              end
            end
          end
        end

        1.times do
          # Fields from the signed list
          ['mode', 'identity', 'assoc_handle'
          ].each do |field|
            test = lambda do
              @message.del_arg(OPENID_NS, field)
              assert_raises(Message::KeyNotFound) {
                call_idres_method(:create_check_auth_request) {}
              }
            end
            define_method("test_create_check_auth_missing_#{field}", test)
          end
        end

        def test_create_check_auth_request_success
          msg = call_idres_method(:create_check_auth_request) {}
          openid_args = @message.get_args(OPENID_NS)
          openid_args['mode'] = 'check_authentication'
          assert_equal(openid_args, msg.to_args)
        end

        def test_create_check_auth_request_success_extra
          @message.set_arg(OPENID_NS, 'cookies', 'chocolate_chip')
          msg = call_idres_method(:create_check_auth_request) {}
          openid_args = @message.get_args(OPENID_NS)
          openid_args['mode'] = 'check_authentication'
          openid_args.delete('cookies')
          assert_equal(openid_args, msg.to_args)
        end
      end

      class CheckAuthResponseTest < Test::Unit::TestCase
        include TestUtil
        include ProtocolErrorMixin

        def setup
          @message = Message.from_openid_args({
            'is_valid' => 'true',
            })
          @assoc = GoodAssoc.new
          @store = MemoryStore.new
          @server_url = 'http://invalid/'
          @endpoint =  DummyEndpoint.new(@server_url)
          @idres = IdResHandler.new(nil, @store, @endpoint)
        end

        def call_process
          @idres.send(:process_check_auth_response, @message)
        end

        def test_valid
          assert_log_matches() { call_process }
        end

        def test_invalid
          for is_valid in ['false', 'monkeys']
            @message.set_arg(OPENID_NS, 'is_valid', 'false')
            assert_protocol_error("Server #{@server_url} responds") {
              assert_log_matches() { call_process }
            }
          end
        end

        def test_valid_invalidate
          @message.set_arg(OPENID_NS, 'invalidate_handle', 'cheese')
          assert_log_matches("Received 'invalidate_handle'") { call_process }
        end

        def test_invalid_invalidate
          @message.set_arg(OPENID_NS, 'invalidate_handle', 'cheese')
          for is_valid in ['false', 'monkeys']
            @message.set_arg(OPENID_NS, 'is_valid', 'false')
            assert_protocol_error("Server #{@server_url} responds") {
              assert_log_matches("Received 'invalidate_handle'") {
                call_process
              }
            }
          end
        end

        def test_invalidate_no_store
          @idres.instance_variable_set(:@store, nil)
          @message.set_arg(OPENID_NS, 'invalidate_handle', 'cheese')
          assert_log_matches("Received 'invalidate_handle'",
                             'Unexpectedly got "invalidate_handle"') {
            call_process
          }
        end
      end
    end
  end
end
