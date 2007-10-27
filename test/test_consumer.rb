require "openid/consumer"
require "test/unit"
require "openid/message"
require "openid/kvform"

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
  end
end
