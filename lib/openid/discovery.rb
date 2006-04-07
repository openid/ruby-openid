require "openid/util"
require "openid/yadis"
require "openid/parse"

require "yadis"
require "yadis/manager"

module OpenID

  class Discovery

    attr_accessor :service_filter
    @@ysm_key = '_openid_services'

    def Discovery.cleanup(session)
      return nil unless session

      service = nil
      ysm = YadisServiceManager.get_manager(session, @@ysm_key)
      if ysm
        service = ysm.current_service
        YadisServiceManager.destroy(session, @@ysm_key)
      end
      
      return service
    end

    def initialize(session, fetcher)
      @session = session
      @fetcher = fetcher
      @service_filter = Proc.new {|s| OpenIDService.from_service(s)}
    end

    def discover(url)
      begin
        identity_url = OpenID::Util.normalize_url(url)
      rescue URI::InvalidURIError
        return nil
      end

      ysm = YadisServiceManager.get_manager(@session, identity_url, @@ysm_key)
      if ysm and ysm.dead_end?
        ysm = nil
        YadisServiceManager.destroy(@session, identity_url, @@ysm_key)
      end

      if ysm.nil?        
        begin
          yadis = YADIS.new(identity_url)
        rescue YADISParseError, YADISHTTPError
          nil
        else
          services = yadis.filter_services([@service_filter])
          ysm = YadisServiceManager.create(@session, identity_url, services, @@ysm_key)
        end
      end

      # URL doesn't support Yadis.  Try old school OpenID discovery
      if ysm.nil?        
        status, service = self.openid_discovery(identity_url)
        if status == SUCCESS
          ysm = YadisServiceManager.create(@session, identity_url, [service], @@ysm_key)
        end
      end
      
      return nil if ysm.nil?
      return ysm.next_service
    end


    def openid_discovery(identity_url)
      begin
        url = OpenID::Util.normalize_url(identity_url)
      rescue URI::InvalidURIError
        return [HTTP_FAILURE, nil]
      end
      ret = @fetcher.get(url)
      return [HTTP_FAILURE, nil] if ret.nil?
      
      consumer_id, data = ret
      server = nil
      delegate = nil
      parse_link_attrs(data) do |attrs|
        rel = attrs["rel"]
        if rel == "openid.server" and server.nil?
          href = attrs["href"]
          server = href unless href.nil?
        end
        
        if rel == "openid.delegate" and delegate.nil?
          href = attrs["href"]
          delegate = href unless href.nil?
        end
      end

      return [PARSE_ERROR, nil] if server.nil?
    
      server_id = delegate.nil? ? consumer_id : delegate

      consumer_id = OpenID::Util.normalize_url(consumer_id)
      server_id = OpenID::Util.normalize_url(server_id)
      server_url = OpenID::Util.normalize_url(server)
                  
      service = FakeOpenIDService.new(consumer_id, server_id, server_url)
      return [SUCCESS, service]
    end    

  end

end
