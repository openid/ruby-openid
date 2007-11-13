require 'openid/extensions/sreg'
require 'openid/message'
require 'openid/server/server'

module OpenID
  module SRegTest
    SOME_SREG_DATA = {
      'nickname'=>'linusaur',
      'postcode'=>'12345',
      'country'=>'US',
      'gender'=>'M',
      'fullname'=>'Leonhard Euler',
      'email'=>'president@whitehouse.gov',
      'dob'=>'0000-00-00',
      'language'=>'en-us',
    }

    class SRegTest < Test::Unit::TestCase

      def test_is11
        assert_equal(SREG_NS_URI, SREG_NS_URI_1_1)
      end

      def test_check_field_name
        SREG_DATA_FIELDS.keys.each{|field_name|
          check_sreg_field_name(field_name)
        }
        assert_raises(ArgumentError) { check_sreg_field_name('invalid') }
        assert_raises(ArgumentError) { check_sreg_field_name(nil) }
      end

      def test_unsupported
        endpoint = FakeEndpoint.new([])
        assert(!supports_sreg?(endpoint))
        assert_equal([SREG_NS_URI_1_1,SREG_NS_URI_1_0], endpoint.checked_uris)
      end

      def test_supported_1_1
        endpoint = FakeEndpoint.new([SREG_NS_URI_1_1])
        assert(supports_sreg?(endpoint))
        assert_equal([SREG_NS_URI_1_1], endpoint.checked_uris)
      end

      def test_supported_1_0
        endpoint = FakeEndpoint.new([SREG_NS_URI_1_0])
        assert(supports_sreg?(endpoint))
        assert_equal([SREG_NS_URI_1_1,SREG_NS_URI_1_0], endpoint.checked_uris)
      end

    end

    class FakeEndpoint < Object
      attr_accessor :checked_uris
      def initialize(supported)
        @supported = supported
        @checked_uris = []
      end

      def uses_extension(namespace_uri)
        @checked_uris << namespace_uri
        return @supported.member?(namespace_uri)
      end
    end

    class FakeMessage < Object
      attr_accessor :namespaces
      attr_accessor :openid1
      def initialize
        @openid1 = false
        @namespaces = NamespaceMap.new
      end
      
      def is_openid1
        return @openid1
      end

    end

    class GetNSTest < Test::Unit::TestCase
      def setup
        @msg = FakeMessage.new
      end

      def test_openid2_empty
        ns_uri = get_sreg_ns(@msg)
        assert_equal('sreg', @msg.namespaces.get_alias(ns_uri))
        assert_equal(SREG_NS_URI, ns_uri)
      end

      def test_openid1_empty
        @msg.openid1 = true
        ns_uri = get_sreg_ns(@msg)
        assert_equal('sreg', @msg.namespaces.get_alias(ns_uri))
        assert_equal(SREG_NS_URI, ns_uri)
      end
      
      def test_openid1defined_1_0
        @msg.openid1 = true
        @msg.namespaces.add(SREG_NS_URI_1_0)
        ns_uri = get_sreg_ns(@msg)
        assert_equal(SREG_NS_URI_1_0, ns_uri)
      end

      def test_openid1_defined_1_0_override_alias
        [true, false].each{|openid_version|
          [SREG_NS_URI_1_0, SREG_NS_URI_1_1].each{|sreg_version|
            ['sreg', 'bogus'].each{|name|
              setup
              @msg.openid1 = openid_version
              @msg.namespaces.add_alias(sreg_version, name)
              ns_uri = get_sreg_ns(@msg)
              assert_equal(name, @msg.namespaces.get_alias(ns_uri))
              assert_equal(sreg_version, ns_uri)
            }
          }
        }
      end
      
      def test_openid1_defined_badly
        @msg.openid1 = true
        @msg.namespaces.add_alias('http://invalid/', 'sreg')
        assert_raises(SRegNamespaceError) { get_sreg_ns(@msg) }
      end

      def test_openid2_defined_badly
        @msg.namespaces.add_alias('http://invalid/', 'sreg')
        assert_raises(SRegNamespaceError) { get_sreg_ns(@msg) }
      end

      def test_openid2_defined_1_0
        @msg.namespaces.add(SREG_NS_URI_1_0)
        ns_uri = get_sreg_ns(@msg)
        assert_equal(SREG_NS_URI_1_0, ns_uri)
      end

      def test_openid1_sreg_ns_from_args
        args = {
          'sreg.optional'=> 'nickname',
          'sreg.required'=> 'dob',
        }

        m = Message.from_openid_args(args)

        assert_equal('nickname', m.get_arg(SREG_NS_URI_1_1, 'optional'))
        assert_equal('dob', m.get_arg(SREG_NS_URI_1_1, 'required'))
      end

    end

    class SRegRequestTest < Test::Unit::TestCase
      def test_construct_empty
        req = SRegRequest.new
        assert_equal([], req.optional)
        assert_equal([], req.required)
        assert_equal(nil, req.policy_url)
        assert_equal(SREG_NS_URI, req.ns_uri)
      end

      def test_construct_fields
        req = SRegRequest.new(['nickname'],['gender'],'http://policy', 'http://sreg.ns_uri')
        assert_equal(['gender'], req.optional)
        assert_equal(['nickname'], req.required)
        assert_equal('http://policy', req.policy_url)
        assert_equal('http://sreg.ns_uri', req.ns_uri)
      end

      def test_construct_bad_fields
        assert_raises(ArgumentError) {SRegRequest.new(['elvis'])}
      end

      def test_from_openid_request_message_copied
        message = Message.from_openid_args({"sreg.required" => "nickname"})
        openid_req = Server::OpenIDRequest.new
        openid_req.message = message
        sreg_req = SRegRequest.from_openid_request(openid_req)
        # check that the message is copied by looking at sreg namespace
        assert_equal(SREG_NS_URI_1_1, message.namespaces.get_namespace_uri('sreg'))
        assert_equal(SREG_NS_URI, sreg_req.ns_uri)
        assert_equal(['nickname'], sreg_req.required)
      end

      def test_from_openid_request_ns_1_0
        message = Message.from_openid_args({'ns.sreg' => SREG_NS_URI_1_0, 
                                             "sreg.required" => "nickname"})
        openid_req = Server::OpenIDRequest.new
        openid_req.message = message
        sreg_req = SRegRequest.from_openid_request(openid_req)
        assert_equal(SREG_NS_URI_1_0, sreg_req.ns_uri)
        assert_equal(['nickname'], sreg_req.required)
      end

      def test_parse_extension_args_empty
        req = SRegRequest.new
        req.parse_extension_args({})
      end

      def test_parse_extension_args_extra_ignored
        req = SRegRequest.new
        req.parse_extension_args({'extra' => 'stuff'})
      end

      def test_parse_extension_args_non_strict
        req = SRegRequest.new
        req.parse_extension_args({'required' => 'stuff'})
        assert_equal([], req.required)
      end
      
      def test_parse_extension_args_strict
        req = SRegRequest.new
        assert_raises(ArgumentError) {
          req.parse_extension_args({'required' => 'stuff'}, true)
        }
      end

      def test_parse_extension_args_policy
        req = SRegRequest.new
        req.parse_extension_args({'policy_url' => 'http://policy'}, true)
        assert_equal('http://policy', req.policy_url)
      end

      def test_parse_extension_args_required_empty
        req = SRegRequest.new
        req.parse_extension_args({'required' => ''}, true)
        assert_equal([], req.required)
      end

      def test_parse_extension_args_optional_empty
        req = SRegRequest.new
        req.parse_extension_args({'optional' => ''},true)
        assert_equal([], req.optional)
      end

      def test_parse_extension_args_optional_single
        req = SRegRequest.new
        req.parse_extension_args({'optional' => 'nickname'},true)
        assert_equal(['nickname'], req.optional)
      end

      def test_parse_extension_args_optional_list
        req = SRegRequest.new
        req.parse_extension_args({'optional' => 'nickname,email'},true)
        assert_equal(['nickname','email'], req.optional)
      end

      def test_parse_extension_args_optional_list_bad_nonstrict
        req = SRegRequest.new
        req.parse_extension_args({'optional' => 'nickname,email,beer'})
        assert_equal(['nickname','email'], req.optional)
      end

      def test_parse_extension_args_optional_list_bad_strict
        req = SRegRequest.new
        assert_raises(ArgumentError) {
          req.parse_extension_args({'optional' => 'nickname,email,beer'}, true)
        }
      end

      def test_parse_extension_args_both_nonstrict
        req = SRegRequest.new
        req.parse_extension_args({'optional' => 'nickname', 'required' => 'nickname'})
        assert_equal(['nickname'], req.required)
        assert_equal([], req.optional)
      end

      def test_parse_extension_args_both_strict
        req = SRegRequest.new
        assert_raises(ArgumentError) {
          req.parse_extension_args({'optional' => 'nickname', 'required' => 'nickname'},true)
        }
      end

      def test_parse_extension_args_both_list
        req = SRegRequest.new
        req.parse_extension_args({'optional' => 'nickname,email', 'required' => 'country,postcode'},true)
        assert_equal(['nickname','email'], req.optional)
        assert_equal(['country','postcode'], req.required)
      end

      def test_all_requested_fields
        req = SRegRequest.new
        assert_equal([], req.all_requested_fields)
        req.request_field('nickname')
        assert_equal(['nickname'], req.all_requested_fields)
        req.request_field('gender', true)
        requested = req.all_requested_fields.sort
        assert_equal(['gender', 'nickname'], requested)
      end

      def test_were_fields_requested
        req = SRegRequest.new
        assert(!req.were_fields_requested?)
        req.request_field('nickname')
        assert(req.were_fields_requested?)
      end

      def test_member
        req = SRegRequest.new
        SREG_DATA_FIELDS.keys.each {|f|
          assert(!req.member?(f))
        }
        assert(!req.member?('something else'))
        req.request_field('nickname')
        SREG_DATA_FIELDS.keys.each {|f|
          assert_equal(f == 'nickname',req.member?(f))
        }
      end

      def test_request_field_bogus
        req = SRegRequest.new
        fields = SREG_DATA_FIELDS.keys
        fields.each {|f| req.request_field(f) }
        assert_equal(fields, req.optional)
        assert_equal([], req.required)

        # By default, adding the same fields over again has no effect
        fields.each {|f| req.request_field(f) }
        assert_equal(fields, req.optional)
        assert_equal([], req.required)

        # Requesting a field as required overrides requesting it as optional
        expected = fields[1..-1]
        overridden = fields[0]
        req.request_field(overridden, true)
        assert_equal(expected, req.optional)
        assert_equal([overridden], req.required)

        fields.each {|f| req.request_field(f, true) }
        assert_equal(fields, req.required)
        assert_equal([], req.optional)
      end

      def test_request_fields_type
        req = SRegRequest.new
        assert_raises(ArgumentError) { req.request_fields('nickname') }
      end

      def test_request_fields
        req = SRegRequest.new
        fields = SREG_DATA_FIELDS.keys

        req.request_fields(fields)
        assert_equal(fields, req.optional)
        assert_equal([], req.required)
        
        # By default, adding the same fields over again has no effect
        req.request_fields(fields)
        assert_equal(fields, req.optional)
        assert_equal([], req.required)

        # required overrides optional
        expected = fields[1..-1]
        overridden = fields[0]
        req.request_fields([overridden], true)
        assert_equal(expected, req.optional)
        assert_equal([overridden], req.required)

        req.request_fields(fields, true)
        assert_equal(fields, req.required)
        assert_equal([], req.optional)

        # optional does not override required
        req.request_fields(fields)
        assert_equal(fields, req.required)
        assert_equal([], req.optional)
      end

      def test_get_extension_args
        req = SRegRequest.new
        assert_equal({}, req.get_extension_args)

        req.request_field('nickname')
        assert_equal({'optional' => 'nickname'}, req.get_extension_args)

        req.request_field('email')
        assert_equal({'optional' => 'nickname,email'}, req.get_extension_args)

        req.request_field('gender', true)
        assert_equal({'optional' => 'nickname,email',
                       'required' => 'gender'}, req.get_extension_args)

        req.request_field('dob', true)
        assert_equal({'optional' => 'nickname,email',
                       'required' => 'gender,dob'}, req.get_extension_args)

        req.policy_url = 'http://policy'
        assert_equal({'optional' => 'nickname,email',
                       'required' => 'gender,dob',
                       'policy_url' => 'http://policy'},
                     req.get_extension_args)

      end
    end

    class DummySuccessResponse
      attr_accessor :message
      def initialize(message, signed_stuff)
        @message = message
        @signed_stuff = signed_stuff
      end
      def get_signed_ns(ns_uri)
        return @signed_stuff
      end
    end


    class SRegResponseTest < Test::Unit::TestCase
      def test_construct
        resp = SRegResponse.new(SOME_SREG_DATA)
        assert_equal(SOME_SREG_DATA, resp.get_extension_args)
        assert_equal(SREG_NS_URI, resp.ns_uri)
        resp2 = SRegResponse.new({}, "http://foo")
        assert_equal({}, resp2.get_extension_args)
        assert_equal('http://foo', resp2.ns_uri)
      end

      def test_from_success_response_signed
        message = Message.from_openid_args({
                                             'sreg.nickname'=>'The Mad Stork',
                                           })
        success_resp = DummySuccessResponse.new(message, {})
        sreg_resp = SRegResponse.from_success_response(success_resp)
        assert_equal({}, sreg_resp.get_extension_args)
      end

      def test_from_success_response_unsigned
        message = Message.from_openid_args({
                                             'ns.sreg' => SREG_NS_URI,
                                             'sreg.nickname' => 'The Mad Stork',
                                           })
        success_resp = DummySuccessResponse.new(message, {})
        sreg_resp = SRegResponse.from_success_response(success_resp, false)
        assert_equal({'nickname' => 'The Mad Stork'}, 
                     sreg_resp.get_extension_args)
      end
    end

    class SendFieldsTest < Test::Unit::TestCase
      # class SendFieldsTest < Object
      def test_send_fields
        # create a request message with simple reg fields
        sreg_req = SRegRequest.new(['nickname', 'email'], ['fullname'])
        req_msg = Message.new
        req_msg.update_args(SREG_NS_URI, sreg_req.get_extension_args)
        req = Server::OpenIDRequest.new
        req.message = req_msg
        req.namespace = req_msg.get_openid_namespace

        # -> checkid_* request

        # create a response
        resp_msg = Message.new
        resp = Server::OpenIDResponse.new(req)
        resp.fields = resp_msg
        sreg_resp = SRegResponse.extract_response(sreg_req, SOME_SREG_DATA)
        resp.add_extension(sreg_resp)

        # <- id_res response

        # extract sent fields
        sreg_data_resp = resp_msg.get_args(SREG_NS_URI)
        assert_equal({'nickname' => 'linusaur',
                       'email'=>'president@whitehouse.gov',
                       'fullname'=>'Leonhard Euler',
                     }, sreg_data_resp)
      end
    end
  end
end

