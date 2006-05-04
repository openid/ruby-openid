require 'rexml/document'

begin
  require 'rubygems'
  require_gem 'ruby-yadis', '>=0.2.3'
rescue LoadError
  require 'yadis/service'
end

module OpenID

  # OpenIDService is an object representation of an OpenID server,
  # and the services it provides.  It contains a useful information such
  # as the server URL, and information about the OpenID identity bound
  # to the server.  OpenIDService object should be produced using the
  # OpenIDService.from_service class method with a Yadis Service object.
  # See the ruby Yadis library for more information:
  #
  # http://www.openidenabled.com/yadis/libraries/ruby
  #
  # Unless you choose to do your own discovery and interface with
  # OpenIDConsumer through the OpenIDConsumer.begin_without_discovery
  # method, you won't need to ever use this object directly.  It is used
  # internally by the OpenIDConsumer object.
  class OpenIDServiceEndpoint < ServiceEndpoint
    
    @@namespace = {'openid' => 'http://openid.net/xmlns/1.0'}
    attr_accessor :service_types, :uri, :yadis_url, :element, :yadis

    # Class method to produce OpenIDService objects. Call with a Yadis Service
    # object.  Will return nil if the Service object does not represent an
    # an OpenID server.
    def OpenIDServiceEndpoint.from_endpoint(service, versions=nil)
      return nil unless OpenIDServiceEndpoint.is_type?(service, versions)

      s = new
      s.service_types = service.service_types
      s.uri = service.uri
      s.element = service.element
      s.yadis = service.yadis
      s.yadis_url = service.yadis.uri
      return s
    end

    # Class method to determine if a Yadis service object is an OpenID server.
    # +versions+ is a list of Strings representing the versions of the OpenID
    # protocol you support.  Only service that match one of the versions will
    # return a value that evaluates to true.  If no +versions+ list is
    # specified, all versions will be accepted.
    def OpenIDServiceEndpoint.is_type?(service, versions=nil)
      # escape the period in the version numbers
      versions.collect! {|v| v.gsub('.', '\.')} if versions
      
      base_url = 'http://openid\.net/signon/'
      base_url += '(' + versions.join('|') + '){1}' if versions
      
      service.service_types.each do |st|
        return true if st.match(base_url)
      end

      return false
    end

    def uses_extension?(extension_url)
      return @service_types.member?(extension_url)
    end

    # Returns the OpenID delegate URL.
    def delegate
      REXML::XPath.each(@element, 'openid:Delegate', @@namespace) do |e|
        return e.text.strip
      end
      return self.consumer_id
    end

    # Returns the OpenID server endpoint URL.
    def server_url
      @uri
    end
    
    # Returns user's URL which resides on the OpenID server.  For
    # example if http://example.com/ delegates to http://example.myopenid.com/,
    # then http://example.myopenid.com/ will be returned by this method.
    def server_id
      self.delegate
    end

    # The URL the user entered to authenticate.  For example, if
    # http://example.com/ delegates to http://example.myopenid.com/, this
    # method will return http://example.com/
    def consumer_id
      @yadis_url
    end
  end


  # Used for providing an OpenIDService like object
  # to the OpenID library for 1.X link rel discovery.
  # See the documentation for OpenID::OpenIDService for more information
  # on what this object does.
  class FakeOpenIDServiceEndpoint < OpenIDServiceEndpoint
    
    def initialize(consumer_id, server_id, server_url)
      @uri = server_url
      @delegate = server_id
      @yadis_url = consumer_id     
      @service_types = ['http://openid.net/signon/1.0']
      @element = nil
      @yadis = nil
    end

    def delegate
      @delegate
    end

    def uses_extension?
      false
    end

  end

end
