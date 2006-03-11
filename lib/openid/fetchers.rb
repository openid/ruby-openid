require "uri"
require "openid/util"

begin
  require "net/https"
rescue LoadError # no openssl
  require "net/http" 
  HAS_OPENSSL_ = false
  OpenID::Util.log('Unable to load openssl. Cannot fetch https urls.')
else
  HAS_OPENSSL_ = true
end



module OpenID

  # Base Object used by consumer to send http messages
  class OpenIDHTTPFetcher

    # Fetch the content of url, following redirects, and return the
    # final url and page data.  Return nil on failure.
    
    def get(url)
      raise NotImplementedError
    end
    
    # Post the body string to url. Return the resulting url and page data.
    # Return nil on failure
    
    def post(url, body)
      raise NotImplementedError
    end
    
  end

  # Implemetation of OpenIDHTTPFetcher that uses ruby's Net::HTTP
  
  class NetHTTPFetcher < OpenIDHTTPFetcher
    
    def initialize(read_timeout=20, open_timeout=20, ssl_verify_mode=nil)
      @read_timeout = read_timeout
      @open_timeout = open_timeout
      
      if HAS_OPENSSL_
        ssl_verify_mode = OpenSSL::SSL::VERIFY_NONE if ssl_verify_mode.nil?
        @ssl_verify_mode = ssl_verify_mode
      end
    end
    
    def get(url)    
      resp, final_url = do_get(url)
      if resp.nil?
        nil
      else
        [final_url, resp.body]
      end
    end
  
    def post(url, body)
      begin
        uri = URI.parse(url)
        http = get_http_obj(uri)
        resp = http.post(uri.request_uri, body,
                         {"Content-type"=>"application/x-www-form-urlencoded"})
      rescue
        nil
      else
        [uri.to_s, resp.body]
      end
    end

    protected
    
    # return a Net::HTTP object ready for use
    
    def get_http_obj(uri)
      http = Net::HTTP.new(uri.host, uri.port)
      http.read_timeout = @read_timeout
      http.open_timeout = @open_timeout

      if uri.scheme == 'https'
        if HAS_OPENSSL_
          http.use_ssl = true
          http.verify_mode = @ssl_verify_mode
        else
          OpenID::Util.log("Trying to fetch HTTPS page without openssl. #{uri.to_s}")
        end
      end

      return http
    end
    
    # do a GET following redirects limit deep
    
    def do_get(url, limit=5)
      if limit == 0
        return nil
      end
      begin
        u = URI.parse(url)
        http = get_http_obj(u)
        resp = http.get(u.request_uri)
      rescue
        nil
      else
        case resp
        when Net::HTTPSuccess then [resp, URI.parse(url).to_s]
        when Net::HTTPRedirection then do_get(resp["location"], limit-1)
        else
          nil
        end
      end
    end
    
  end
  
end
