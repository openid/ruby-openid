require 'test/unit'
require 'net/http'
require 'webrick'

require 'openid/fetchers'

require 'stringio'

module HttpResultAssertions
  def assert_http_result_is(expected_code, result)
    assert_equal expected_code.to_s, result.code
    assert_equal "the expected body", result.body
  end
end

class FetcherTestCase < Test::Unit::TestCase
  include HttpResultAssertions


  @@cases =
    [
     ['/success', 200],
#      ['/301redirect', 200],
#      ['/302redirect', 200],
#      ['/303redirect', 200],
#      ['/307redirect', 200],
     ['/notfound', 404],
     ['/badreq', 400],
     ['/forbidden', 403],
     ['/error', 500],
     ['/server_error', 503],
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

  class HarnessBroke < Exception
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
      # @server.mount_proc('/301redirect', _redirect_with_code(301))
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

  def test_cases
    for path, expected_code in @@cases
      begin
        uri = _uri_build(path)
        result = @fetcher.fetch(uri)
        assert_http_result_is expected_code, result
      rescue Test::Unit::AssertionFailedError => err
        if result.code == '500' && expected_code != 500
          # Looks like our WEBrick harness broke.
          raise "Status #{result.code} from case #{path}.  Logs:\n#{@logfile.string}"
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
