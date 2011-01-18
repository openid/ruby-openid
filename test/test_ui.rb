require 'openid/extensions/ui'
require 'openid/message'
require 'openid/server'
require 'test/unit'

module OpenID
  module UITest
    class UIRequestTestCase < Test::Unit::TestCase

      def setup
        @req = UI::Request.new
      end

      def test_construct
        assert_nil @req.mode
        assert_nil @req.icon
        assert_nil @req.lang
        assert_equal 'ui', @req.ns_alias

        req2 = UI::Request.new("popup", true, "ja-JP")
        assert_equal "popup", req2.mode
        assert_equal true, req2.icon
        assert_equal "ja-JP", req2.lang
      end

      def test_add_mode
        @req.mode = "popup"
        assert_equal "popup", @req.mode
      end

      def test_add_icon
        @req.icon = true
        assert_equal true, @req.icon
      end

      def test_add_lang
        @req.lang = "ja-JP"
        assert_equal "ja-JP", @req.lang
      end

      def test_get_extension_args
        assert_equal({}, @req.get_extension_args)
        @req.mode = "popup"
        assert_equal({'mode' => 'popup'}, @req.get_extension_args)
        @req.icon = true
        assert_equal({'mode' => 'popup', 'icon' => true}, @req.get_extension_args)
        @req.lang = "ja-JP"
        assert_equal({'mode' => 'popup', 'icon' => true, 'lang' => 'ja-JP'}, @req.get_extension_args)
      end

      def test_parse_extension_args
        args = {'mode' => 'popup', 'icon' => true, 'lang' => 'ja-JP'}
        @req.parse_extension_args args
        assert_equal "popup", @req.mode
        assert_equal true, @req.icon
        assert_equal "ja-JP", @req.lang
      end

      def test_parse_extension_args_empty
        @req.parse_extension_args({})
        assert_nil @req.mode
        assert_nil @req.icon
        assert_nil @req.lang
      end

      def test_from_openid_request
        openid_req_msg = Message.from_openid_args(
          'mode' => 'checkid_setup',
          'ns' => OPENID2_NS,
          'ns.ui' => UI::NS_URI,
          'ui.mode' => 'popup',
          'ui.icon' => true,
          'ui.lang' => 'ja-JP'
        )
        oid_req = Server::OpenIDRequest.new
        oid_req.message = openid_req_msg
        req = UI::Request.from_openid_request oid_req
        assert_equal "popup", req.mode
        assert_equal true, req.icon
        assert_equal "ja-JP", req.lang
      end

      def test_from_openid_request_no_ui_params
        message = Message.new
        openid_req = Server::OpenIDRequest.new
        openid_req.message = message
        ui_req = UI::Request.from_openid_request openid_req
        assert ui_req.nil?
      end

    end
  end
end
