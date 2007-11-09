require "openid/message"
require "openid/protocolerror"
require "openid/kvpost"

module OpenID
  class Consumer
    class IdResHandler
      attr_accessor :openid1_nonce_query_arg_name

      def initialize(message, return_to, store=nil, endpoint=nil)
        @store = store # Fer the nonce and invalidate_handle
        @message = message
        @endpoint = endpoint
        @return_to = return_to
        @signed_list = nil
        @openid1_nonce_query_arg_name = 'rp_nonce'
      end

      def id_res
        check_for_fields
        verify_return_to
        verify_discovery_results
        check_signature
        check_nonce

        signed_fields = signed_list.map {|x| 'openid.' + x}
        SuccessResponse(@endpoint, @message, signed_fields)
      end

      protected

      def server_url
        @endpoint.nil? ? nil : @endpoint.server_url
      end

      def openid_namespace
        @message.get_openid_namespace
      end

      def fetch(field, default=NO_DEFAULT)
        @message.get_arg(OPENID_NS, field, default)
      end

      def signed_list
        if @signed_list.nil?
          signed_list_str = fetch('signed', nil)
          if signed_list_str.nil?
            raise ProtocolError, 'Response missing signed list'
          end

          @signed_list = signed_list_str.split(',', -1)
        end
        @signed_list
      end

      def check_for_fields
        # XXX: if a field is missing, we should not have to explicitly
        # check that it's present, just make sure that the fields are
        # actually being used by the rest of the code in
        # tests. Although, which fields are signed does need to be
        # checked somewhere.
        basic_fields = ['return_to', 'assoc_handle', 'sig', 'signed']
        basic_sig_fields = ['return_to', 'identity']

        case openid_namespace
        when OPENID2_NS
          require_fields = basic_fields + ['op_endpoint']
          require_sigs = basic_sig_fields +
            ['response_nonce', 'claimed_id', 'assoc_handle',]
        when OPENID1_NS
          require_fields = basic_fields + ['identity']
          require_sigs = basic_sig_fields
        else
          raise RuntimeError, "check_for_fields doesn't know about "\
                              "namespace #{openid_namespace.inspect}"
        end

        require_fields.each do |field|
          if !@message.has_key?(OPENID_NS, field)
            raise ProtocolError, "Missing required field #{field}"
          end
        end

        require_sigs.each do |field|
          # Field is present and not in signed list
          if @message.has_key?(OPENID_NS, field) && !signed_list.member?(field)
            raise ProtocolError, "#{field.inspect} not signed"
          end
        end
      end

      def verify_return_to
        msg_return_to = URI.parse(fetch('return_to'))
        verify_return_to_args(msg_return_to)
        if !@return_to.nil?
          verify_return_to_base(msg_return_to)
        end
      end

      def verify_return_to_args(msg_return_to)
        return_to_parsed_query = {}
        if !msg_return_to.query.nil?
          CGI.parse(msg_return_to.query).each_pair do |k, vs|
            return_to_parsed_query[k] = vs[0]
          end
        end
        query = @message.to_post_args
        return_to_parsed_query.each_pair do |rt_key, rt_val|
          msg_val = query[rt_key]
          if msg_val.nil?
            raise ProtocolError, "Message missing return_to argument #{rt_key}"
          elsif msg_val != rt_val
            raise ProtocolError, ("Parameter #{rt_key} value "\
                                  "#{msg_val.inspect} does not match "\
                                  "return_to's value #{rt_val.inspect}")
          end
        end
        @message.get_args(BARE_NS).each_pair do |bare_key, bare_val|
          if return_to_parsed_query[bare_key] != bare_val
            raise ProtocolError, ("Parameter #{bare_key} does not match "\
                                  "return_to URL")
          end
        end
      end

      def verify_return_to_base(msg_return_to)
        app_parsed = URI.parse(@return_to)
        [:scheme, :host, :port, :path].each do |meth|
          if msg_return_to.send(meth) != app_parsed.send(meth)
            raise ProtocolError, "return_to #{meth.to_s} does not match"
          end
        end
      end

      # Raises ProtocolError if the signature is bad
      def check_signature
        if @store.nil?
          assoc = nil
        else
          assoc = @store.get_association(server_url, fetch('assoc_handle'))
        end

        if assoc.nil?
          check_auth
        else
          if assoc.expires_in <= 0
            # XXX: It might be a good idea sometimes to re-start the
            # authentication with a new association. Doing it
            # automatically opens the possibility for
            # denial-of-service by a server that just returns expired
            # associations (or really short-lived associations)
            raise ProtocolError, "Association with #{server_url} expired"
          elsif !assoc.check_message_signature(@message)
            raise ProtocolError, "Bad signature in response from #{server_url}"
          end
        end
      end

      def check_auth
        Util.log("Using 'check_authentication' with #{server_url}")
        begin
          request = create_check_auth_request
        rescue Message::KeyNotFound => why
          raise ProtocolError, "Could not generate 'check_authentication' "\
                               "request: #{why.message}"
        end

        begin
          response = OpenID.make_kv_post(request, server_url)
        rescue ServerError => why
          raise ProtocolError, "Error from #{server_url} during "\
                               "check_authentication: #{why.message}"
        end

        process_check_auth_response(response)
      end

      def create_check_auth_request
        check_args = {}

        # Arguments that are always passed to the server and not
        # included in the signature.
        for k in ['assoc_handle', 'sig', 'signed', 'invalidate_handle']
          val = fetch(k, nil)
          if !val.nil?
            check_args[k] = val
          end
        end

        for k in signed_list
          val = @message.get_aliased_arg(k, NO_DEFAULT)
          check_args[k] = val
        end

        check_args['mode'] = 'check_authentication'
        return Message.from_openid_args(check_args)
      end

      # Process the response message from a check_authentication
      # request, invalidating associations if requested.
      def process_check_auth_response(response)
        is_valid = response.get_arg(OPENID_NS, 'is_valid', 'false')

        invalidate_handle = response.get_arg(OPENID_NS, 'invalidate_handle')
        if !invalidate_handle.nil?
          Util.log("Received 'invalidate_handle' from server #{server_url}")
          if @store.nil?
            Util.log('Unexpectedly got "invalidate_handle" without a store!')
          else
            @store.remove_association(server_url, invalidate_handle)
          end
        end

        if is_valid != 'true'
          raise ProtocolError, ("Server #{server_url} responds that the "\
                                "'check_authentication' call is not valid")
        end
      end

      def check_nonce
        case openid_namespace
        when OPENID1_NS
          nonce = @message.get_arg(BARE_NS, openid1_nonce_query_arg_name)

          # We generated the nonce, so it uses the empty string as the
          # server URL
          server_url = ''
        when OPENID2_NS
          nonce = @message.get_arg(OPENID2_NS, 'response_nonce')
          server_url = self.server_url
        else
          raise StandardError, 'Not reached'
        end

        if nonce.nil?
          raise ProtocolError, 'Nonce missing from response'
        end

        begin
          time, extra = Nonce.split_nonce(nonce)
        rescue ArgumentError => why
          raise ProtocolError, "Malformed nonce: #{nonce.inspect}"
        end

        if !@store.nil? && !@store.use_nonce(server_url, time, extra)
          raise ProtocolError, ("Nonce already used or out of range: "\
                               "#{nonce.inspect}")
        end
      end
    end
  end
end
