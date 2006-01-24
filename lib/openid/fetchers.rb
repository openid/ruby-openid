require "uri"
require "net/http"

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
    
    def initialize(read_timeout=20, open_timeout=20)
      @read_timeout = read_timeout
      @open_timeout = open_timeout
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
        u = URI.parse(url)
        http = get_http_obj(u.host, u.port)
        resp = http.post(u.request_uri, body,
                         {"Content-type"=>"application/x-www-form-urlencoded"})
      rescue
        nil
      else
        [u.to_s, resp.body]
      end
    end

    protected
    
    # return a Net::HTTP object ready for use
    
    def get_http_obj(host, port)
      http = Net::HTTP.start(host, port)
      http.read_timeout = @read_timeout
      http.open_timeout = @open_timeout
      http
    end
    
    # do a GET following redirects limit deep
    
    def do_get(url, limit=5)
      if limit == 0
        return nil
      end
      begin
        u = URI.parse(url)
        http = get_http_obj(u.host, u.port)
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
