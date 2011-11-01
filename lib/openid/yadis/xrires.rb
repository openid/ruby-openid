require "cgi"
require "openid/yadis/xri"
require "openid/yadis/xrds"
require "openid/fetchers"

module OpenID

  module Yadis

    module XRI

      class XRIHTTPError < StandardError; end

      class ProxyResolver

        DEFAULT_PROXY ||= 'http://proxy.xri.net/'

        def initialize(proxy_url=nil)
          if proxy_url
            @proxy_url = proxy_url
          else
            @proxy_url = DEFAULT_PROXY
          end

          @proxy_url += '/' unless @proxy_url.match('/$')
        end

        def query_url(xri, service_type=nil)
          # URI normal form has a leading xri://, but we need to strip
          # that off again for the QXRI.  This is under discussion for
          # XRI Resolution WD 11.
          qxri = XRI.to_uri_normal(xri)[6..-1]
          hxri = @proxy_url + CGI::escape( qxri )
          args = {'_xrd_r' => 'application/xrds+xml'}          
          args['_xrd_t'] = service_type if service_type

          return XRI.append_args(hxri, args)
        end

        def query(xri)
          # these can be query args or http headers, needn't be both.
          # headers = {'Accept' => 'application/xrds+xml;sep=true'}

          url = self.query_url(xri)
          begin
            response = OpenID.fetch(url)
          rescue
            raise XRIHTTPError, "Could not fetch #{xri}, #{$!}"
          end
          raise XRIHTTPError, "Fetching #{xri} returned nothing" if response.nil?

          xrds = Yadis::parseXRDS(response.body)
          raise XRIHTTPError, "Fetching #{xri} did not return an XRDS" if xrds.nil?
          canonicalID = Yadis::get_canonical_id(xri, xrds)

          return canonicalID, Yadis::services(xrds)
        end
      end

      def self.urlencode(args)
        a = []
        args.each do |key, val|
          a << (CGI::escape(key) + "=" + CGI::escape(val))
        end
        a.join("&")
      end

      def self.append_args(url, args)
        return url if args.length == 0

        # rstrip question marks
        rstripped = url.dup
        while rstripped[-1].chr == '?'
          rstripped = rstripped[0...rstripped.length-1]
        end

        if rstripped.index('?')
          sep = '&'
        else
          sep = '?'
        end

        return rstripped + sep + XRI.urlencode(args)
      end

    end

  end

end
