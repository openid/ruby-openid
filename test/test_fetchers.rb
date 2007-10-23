require 'test/unit'
require 'net/http'
require 'webrick'

require 'openid/fetchers'

module HttpResultAssertions
  def assert_http_success(result)
    _wrap_assertion do
      unless result.code == '200'
        msg = "Not success: #{result}"
        raise Test::Unit::AssertionFailedError.new(msg)
      end
    end
  end
end

class FetcherTestCase < Test::Unit::TestCase
  include HttpResultAssertions

  def setup
    @fetcher = OpenID::StandardFetcher.new
    @server = WEBrick::HTTPServer.new(:Port => 0)
    @server_thread = Thread.new {
      @server.mount_proc('/success') { |req, resp|
        resp.body = "hi"
      }
      @server.start
    }
    @uri = URI::HTTP.build({
      :host => @server.config[:ServerName],
      :port => @server.config[:Port],
    })
  end

  def teardown
    @server.shutdown
    @server_thread.join
  end

  def test_fetch200
    @uri.path = '/success'
    assert_http_success @fetcher.fetch(@uri)
  end
end
