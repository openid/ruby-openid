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

  class StandardFetcher
    def fetch(url, body=nil, headers=nil)
      response = Net::HTTP.get_response(url)
      case response
      when Net::HTTPRedirection
        redirect_url = URI.parse(response["location"])
        return fetch(redirect_url, body, headers)
      else
        return HTTPResponse._from_net_response(response, url)
      end
    end
  end
end
