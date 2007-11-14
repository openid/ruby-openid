require "openid/consumer/idres.rb"
require "openid/consumer/checkid_request.rb"
require "openid/consumer/associationmanager.rb"
require "openid/consumer/responses.rb"
require "openid/consumer/discovery_manager"
require "openid/consumer/discovery"
require "openid/message"
require "openid/yadis/discovery"
require "openid/store/nonce"

module OpenID
  class Consumer
    attr_accessor :session_key_prefix

    def initialize(session, store)
      @session = session
      @store = store
      @session_key_prefix = 'OpenID::Consumer::'
    end

    def begin(openid_identifier, anonymous=false)
      manager = discovery_manager(openid_identifier)
      service = manager.get_next_service(&method(:discover))

      if service.nil?
        raise Yadis::DiscoveryFailure.new("No usable OpenID services were "\
                                          "found for "\
                                          "#{openid_identifier.inspect}", nil)
      else
        begin_without_discovery(service, anonymous)
      end
    end

    def begin_without_discovery(service, anonymous)
      assoc = association_manager(service).get_association
      checkid_request = CheckIDRequest.new(assoc, service)
      checkid_request.anonymous = anonymous

      if service.compatibility_mode
        rt_args = checkid_request.return_to_args
        rt_args[Consumer.openid1_return_to_nonce_name] = Nonce.mk_nonce
        rt_args[Consumer.openid1_return_to_claimed_id_name] =
          service.claimed_id
      end

      self.last_requested_endpoint = service
      return checkid_request
    end

    def complete(query, return_to)
      message = Message.from_post_args(query)
      mode = message.get_arg(OPENID_NS, 'mode', 'invalid')
      begin
        meth = method('complete_' + mode)
      rescue NameError
        meth = method(:complete_invalid)
      end
      response = meth.call(message, return_to)
      cleanup_last_requested_endpoint
      if [SUCCESS, CANCEL].member?(response.status)
        cleanup_session
      end
      return response
    end

    protected

    # Session stuff

    def session_get(name)
      @session[session_key(name)]
    end

    def session_set(name, val)
      @session[session_key(name)] = val
    end

    def session_key(suffix)
      @session_key_prefix + suffix
    end

    def last_requested_endpoint
      session_get('last_requested_endpoint')
    end

    def last_requested_endpoint=(endpoint)
      session_set('last_requested_endpoint', endpoint)
    end

    def cleanup_last_requested_endpoint
      @session.delete(session_key('last_requested_endpoint'))
    end

    def discovery_manager(openid_identifier)
      DiscoveryManager.new(@session, openid_identifier, @session_key_prefix)
    end

    def cleanup_session
      discovery_manager(nil).cleanup(true)
    end


    def discover(identifier)
      OpenID.discover(identifier)
    end

    def negotiator
      DefaultNegotiator
    end

    def association_manager(service)
      AssociationManager.new(@store, service.server_url,
                             service.compatibility_mode, negotiator)
    end

    def handle_idres(message, return_to)
      IdResHandler.new(message, return_to, @store, last_requested_endpoint)
    end

    # complete() mode handlers

    def complete_invalid(message, unused_return_to)
      mode = message.get_arg(OPENID_NS, 'mode', '<No mode set>')
      return FailureResponse.new(last_requested_endpoint,
                                 "Invalid openid.mode: #{mode}")
    end

    def complete_cancel(unused_message, unused_return_to)
      return CancelResponse.new(last_requested_endpoint)
    end

    def complete_error(message, unused_return_to)
      error = message.get_arg(OPENID_NS, 'error')
      contact = message.get_arg(OPENID_NS, 'contact')
      reference = message.get_arg(OPENID_NS, 'reference')

      return FailureResponse.new(last_requested_endpoint,
                                 error, contact, reference)
    end

    def complete_setup_needed(message, unused_return_to)
      if message.is_openid1
        return complete_invalid(message, nil)
      else
        return SetupNeededResponse.new(last_requested_endpoint, nil)
      end
    end

    def complete_id_res(message, return_to)
      if message.is_openid1
        setup_url = message.get_arg(OPENID1_NS, 'user_setup_url')
        if !setup_url.nil?
          return SetupNeededResponse.new(last_requested_endpoint, setup_url)
        end
      end

      begin
        idres = handle_idres(message, return_to)
      rescue Yadis::DiscoveryFailure, ProtocolError => why
        return FailureResponse.new(last_requested_endpoint, why.message)
      else
        return SuccessResponse.new(idres.endpoint, message,
                                     idres.signed_fields)
      end
    end
  end
end
