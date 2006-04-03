require 'rexml/document'

module OpenID

  class OpenIDService

    @@namespace = {'openid' => 'http://openid.net/xmlns/1.0'}
    attr_accessor :service_type, :uri, :yadis_url, :element, :yadis, :version

    def OpenIDService.from_service(service, versions=nil)
      return nil unless OpenIDService.is_type?(service, versions)

      s = new
      s.service_type = service.service_type
      s.uri = service.uri
      s.element = service.element
      s.yadis = service.yadis
      s.yadis_url = service.yadis.uri

      match = s.service_type.match('http://openid\.net/signon/(.*)')
      if match
        s.version = match[1]
      else
        s.version = nil
      end

      return s
    end

    def OpenIDService.is_type?(service, versions=nil)
      # escape the period in the version numbers
      versions.collect! {|v| v.gsub('.', '\.')} if versions
      
      base_url = 'http://openid\.net/signon/'
      base_url += '(' + versions.join('|') + '){1}' if versions
      
      service.service_type.match(base_url)
    end

    def delegate
      REXML::XPath.each(@element, 'openid:Delegate', @@namespace) do |e|
        return e.text.strip
      end
      return self.consumer_id
    end

    def extensions
      extensions = []
      REXML::XPath.each(@element, 'openid:Extension', @@namespace) do |e|
        extensions << e.text.strip
      end
      extensions
    end

    def server_url
      @uri
    end

    def server_id
      self.delegate
    end

    def consumer_id
      @yadis_url
    end
  end


  # Used for providing an OpenIDService like object
  # to the OpenID library for 1.X link rel discovery.
  class FakeOpenIDService < OpenIDService
    
    def initialize(consumer_id, server_id, server_url)
      @uri = server_url
      @delegate = server_id
      @yadis_url = consumer_id     
      @service_type = 'http://openid.net/signon/1.0'
      @version = '1.0'
      @element = nil
      @yadis = nil
    end

    def delegate
      @delegate
    end

    def extensions
      []
    end

  end

end
