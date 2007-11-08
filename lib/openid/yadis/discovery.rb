
require 'openid/fetchers'
require 'openid/yadis/constants'
require 'openid/yadis/parsehtml'

module OpenID

  module Yadis

    class DiscoveryFailure < StandardError
      attr_accessor :identity_url

      # Raised when a YADIS protocol error occurs in the discovery
      # process
      def initialize(message, http_response)
        super(message)
        @identity_url = nil
        @http_response = http_response
      end
    end

    class DiscoveryResult
      # Contains the result of performing Yadis discovery on a URI

      attr_accessor :request_uri, :normalized_uri, :xrds_uri, :content_type, :response_text

      def initialize(request_uri)
        # Initialize the state of the object
        #
        # sets all attributes to None except the request_uri
        @request_uri = request_uri

        # The result of following redirects from the request_uri
        @normalized_uri = nil

        # The URI from which the response text was returned (set to
        # None if there was no XRDS document found)
        @xrds_uri = nil

        # The content-type returned with the response_text
        @content_type = nil

        # The document returned from the xrds_uri
        @response_text = nil
      end

      def used_yadis_location?
        # Was the Yadis protocol's indirection used?
        return @normalized_uri != @xrds_uri
      end

      def is_xrds
        # Is the response text supposed to be an XRDS document?
        return (used_yadis_location?() or
                @content_type == YADIS_CONTENT_TYPE)
      end
    end

    def self.discover(uri)
      # Discover services for a given URI.
      #
      # uri: The identity URI as a well-formed http or https URI. The
      # well-formedness and the protocol are not checked, but the
      # results of this function are undefined if those properties do
      # not hold.
      #
      # returns a DiscoveryResult object
      #
      # @raises Exception: Any exception that can be raised by
      # fetching a URL with the given fetcher.
      #
      # @raises DiscoveryFailure: When the HTTP response does not have
      # a 200 code.
      result = DiscoveryResult.new(uri)
      resp = OpenID.fetch(uri, {'Accept' => YADIS_ACCEPT_HEADER})
      if resp.code != 200
        raise DiscoveryFailure.new(
                "HTTP Response status from identity URL host is not 200. " +
                "Got status #{resp.code}", resp)
      end

      # Note the URL after following redirects
      result.normalized_uri = resp.final_url

      # Attempt to find out where to go to discover the document or if
      # we already have it
      result.content_type = resp['content-type']

      result.xrds_uri = self.where_is_yadis?(resp)

      if result.xrds_uri and result.used_yadis_location?
        resp = OpenID.fetch(result.xrds_uri)
        if resp.code != 200
            exc = DiscoveryFailure.new(
                    "HTTP Response status from Yadis host is not 200. " +
                    "Got status #{resp.code}", resp)
            exc.identity_url = result.normalized_uri
            raise exc
        end

        result.content_type = resp['content-type']
      end

      result.response_text = resp.body
      return result
    end

    def self.where_is_yadis?(resp)
      # Given a HTTPResponse, return the location of the Yadis
      # document.
      #
      # May be the URL just retrieved, another URL, or None, if I
      # can't find any.
      #
      # [non-blocking]
      #
      # @returns: str or None

      # Attempt to find out where to go to discover the document or if
      # we already have it
      content_type = resp['content-type']

      # According to the spec, the content-type header must be an
      # exact match, or else we have to look for an indirection.
      if (!content_type.nil? and
          content_type.split(';', 2)[0].downcase == YADIS_CONTENT_TYPE)
        return resp.final_url
      else
        # Try the header
        yadis_loc = resp[YADIS_HEADER_NAME.downcase]

        if yadis_loc.nil?
          # Parse as HTML if the header is missing.
          #
          # XXX: do we want to do something with content-type, like
          # have a whitelist or a blacklist (for detecting that it's
          # HTML)?
          yadis_loc = Yadis.html_yadis_location(resp.body)
        end
      end

      return yadis_loc
    end

  end

end
