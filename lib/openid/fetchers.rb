require 'net/http'

module OpenID
  # Our HTTPResponse class extends Net::HTTPResponse with an additional
  # method, final_url.
  class HTTPResponse
    attr_accessor :final_url

    attr_accessor :_response

    def self._from_net_response(response, final_url)
      me = self.new
      me._response = response
      me.final_url = final_url
      return me
    end

    def method_missing(method, *args)
      @_response.send(method, *args)
    end
  end

  class HTTPRedirectLimitReached < StandardError
  end
  
  class StandardFetcher

    # FIXME: Use an OpenID::VERSION constant here.
    USER_AGENT = "ruby-openid/VERSION (#{PLATFORM})"

    REDIRECT_LIMIT = 5

    def fetch(url, body=nil, headers=nil, redirect_limit=REDIRECT_LIMIT)
      headers ||= {}
      headers['User-agent'] ||= USER_AGENT
      httpthing = Net::HTTP.new(url.host, url.port)
      if body.nil?
        response = httpthing.request_get(url.request_uri, headers)
      else
        headers["Content-type"] ||= "application/x-www-form-urlencoded"
        response = httpthing.request_post(url.request_uri, body, headers)
      end
      case response
      when Net::HTTPRedirection
        redirect_url = URI.parse(response["location"])
        if redirect_limit <= 0
          raise HTTPRedirectLimitReached.new(
            "Too many redirects, not fetching #{redirect_url}")
        end
        return fetch(redirect_url, body, headers, redirect_limit - 1)
      else
        return HTTPResponse._from_net_response(response, url)
      end
    end
  end
end
