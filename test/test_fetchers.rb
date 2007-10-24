require 'test/unit'
require 'net/http'
require 'webrick'

require 'openid/fetchers'

require 'stringio'

module HttpResultAssertions
  def assert_http_result_is(expected, result)
    assert_equal expected.code, result.code
    assert_equal expected.body, result.body
    assert_equal expected.final_url, result.final_url
  end
end


class FetcherTestCase < Test::Unit::TestCase
  include HttpResultAssertions

  class ExpectedResponse < Net::HTTPResponse
    attr_reader :final_url

    def initialize(code, final_url, body="the expected body",
                   httpv="1.1", msg=nil)
      super(httpv, code, msg)
      @code = code
      @body = body
      @final_url = final_url
    end

    def body
      @body
    end
  end

  @@cases =
    [
     # path, status code, expected url (nil = default to path)
     ['/success', 200, nil],
     ['/notfound', 404, nil],
     ['/badreq', 400, nil],
     ['/forbidden', 403, nil],
     ['/error', 500, nil],
     ['/server_error', 503, nil],
     ['/301redirect', 200, '/success'],
     ['/302redirect', 200, '/success'],
     ['/303redirect', 200, '/success'],
     ['/307redirect', 200, '/success'],
    ]

  def _redirect_with_code(code)
    lambda { |req, resp|
      resp.status = code
      resp['Location'] = _uri_build('/success')
    }
  end

  def _respond_with_code(code)
    lambda { |req, resp|
      resp.status = code
      resp.body = "the expected body"
    }
  end

  def setup
    @fetcher = OpenID::StandardFetcher.new
    @logfile = StringIO.new
    @weblog = WEBrick::Log.new(logfile=@logfile)
    @server = WEBrick::HTTPServer.new(:Port => 0,
                                      :Logger => @weblog,
                                      :AccessLog => [])
    @server_thread = Thread.new {
      @server.mount_proc('/success', _respond_with_code(200))
      @server.mount_proc('/301redirect', _redirect_with_code(301))
      @server.mount_proc('/302redirect', _redirect_with_code(302))
      @server.mount_proc('/303redirect', _redirect_with_code(303))
      @server.mount_proc('/307redirect', _redirect_with_code(307))
      @server.mount_proc('/badreq', _respond_with_code(400))
      @server.mount_proc('/forbidden', _respond_with_code(403))
      @server.mount_proc('/notfound', _respond_with_code(404))
      @server.mount_proc('/error', _respond_with_code(500))
      @server.mount_proc('/server_error', _respond_with_code(503))
      @server.start
    }
    @uri = _uri_build
  end

  def _uri_build(path='/')
    URI::HTTP.build({
      :host => @server.config[:ServerName],
      :port => @server.config[:Port],
      :path => path,
    })
  end

  def teardown
    @server.shutdown
    @server_thread.join
  end

  def test_final_url_tainted
    uri = _uri_build('/301redirect')
    result = @fetcher.fetch(uri)
    assert result.final_url.host.tainted?
    assert result.final_url.path.tainted?
  end

  def test_cases
    for path, expected_code, expected_url in @@cases
      uri = _uri_build(path)
      if expected_url.nil?
        expected_url = uri
      else
        expected_url = _uri_build(expected_url)
      end

      expected = ExpectedResponse.new(expected_code.to_s, expected_url)
      result = @fetcher.fetch(uri)

      begin
        assert_http_result_is expected, result
      rescue Test::Unit::AssertionFailedError => err
        if result.code == '500' && expected_code != 500
          # Looks like our WEBrick harness broke.
          msg = <<EOF
Status #{result.code} from case #{path}.  Logs:
#{@logfile.string}
EOF
          raise msg
        end

        # Wrap failure messages so we can tell which case failed.
        new_msg = "#{path}: #{err.message.to_s}"
        new_err = Test::Unit::AssertionFailedError.new(new_msg)
        new_err.set_backtrace(err.backtrace)
        raise new_err
      end
    end
  end
end
