require 'net/http'

module OpenID
  class StandardFetcher
    def fetch(url, body=nil, headers=nil)
      Net::HTTP.get_response(url)
    end
  end
end
