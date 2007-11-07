require "testutil"
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

      class CheckSigTest < Test::Unit::TestCase
        include ProtocolErrorMixin

        GOODSIG = '[A Good Signature]'

        class GoodAssoc
          attr_accessor :handle

          def initialize(handle='-blah-')
            @handle = handle
          end

          def expires_in
            3600
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

        def call_check_sig
          idres = IdResHandler.new(@message, @store, @endpoint)
          idres.extend(InstanceDefExtension)

          # Raise an exception if check_auth is called
          idres.instance_def(:check_auth) do
            fail("Should not call check_auth")
          end

          idres.send(:check_signature)
        end

        def test_sign_good
          assert_nothing_raised { call_check_sig }
        end

        def test_bad_sig
          @message.set_arg(OPENID_NS, 'sig', 'bad sig!')
          assert_protocol_error('Bad signature') { call_check_sig }
        end
      end

    end
  end
end
