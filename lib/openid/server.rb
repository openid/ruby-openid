require 'cgi'

require 'openid/util'
require 'openid/dh'
require 'openid/trustroot'

module OpenID

  # Status code returned OpenIDServer.get_openid_response when the framework
  # using the library should issue a redirect to the user's browser.
  REDIRECT     = 'redirect'

  # Status code is returned by OpenIDServer.get_openid_response when the
  # library has determined that it's up to the application and user to
  # fix the reason the library isn't authorized to return a successful
  # authentication response.
  DO_AUTH      = 'do_auth'

  # Status code returned by OpenIDServer.get_openid_response when there
  # are no openid arguments provided. Standard behavior is to render a
  # page saying that this URL is an OpenID server.
  DO_ABOUT     = 'do_about'

  # Status code is returned by OpenIDServer.get_openid_response when the
  # server should send a 200 response code and an exact message body.
  # This is for informing a remote site everything worked correctly. 
  REMOTE_OK    = 'exact_ok'

  # Status code is returned by OpenIDServer.get_openid_response when the
  # server should send a 400 response code and an exact message body.
  # This is for informing a remote site that an error occured while
  # processing the request.
  REMOTE_ERROR = 'exact_error'
  
  # Status code is returned by OpenIDServer.get_openid_response when
  # something went wrong, and the library isn't able to find an
  # appropriate in-protocol response.  When this happens, a short
  # plaintext description of the error will be provided.  The server
  # will probably want to return some sort of error page here, but its
  # contents are not strictly prescribed, like those of the
  # OpenID::REMOTE_ERROR case.
  LOCAL_ERROR  = 'local_error'

  # Below is the documentation for the OpenIDServer class.  The only
  # part of the server library which has to be used and is not
  # documented here is the store for associations.  See
  # OpenID::OpenIDStore and OpenID::FilesystemOpenIDStore for more
  # information.
  #
  # ==Overview
  #
  # There are two different classes of requests that identity servers
  # need to be able to handle.  First are the requests made directly
  # by identity consumers.  Second are the requests made indirectly,
  # via redirects sent to the user's web browser.
  #
  # The first class are the requests made to it directly by identity
  # consumers.  These are HTTP POST requests made to the published
  # OpenID server URL.  There are two types of these requests, requests
  # to create an association, and requests to verify identity requests
  # signed with a secret that is entirely private to the server.
  #
  # The second class are the requests made through redirects.  These
  # are HTTP GET requests coming from the user's web browser.  For
  # these requests, the identity server must perform several steps.
  # It has to determine the identity of the user making the request,
  # determine if they are allowed to use the identity requested, and
  # then take the correct action depending on the exact form of the
  # request and the answers to those questions.
  #
  # ==Library Design
  #
  # This server library is designed to make dealing with both classes
  # of requests as straightforward as possible.
  #
  # At a high level, there are two parts of the library which are
  # important.  First, there is the OpenIDServer class.
  # Second, there is the OpenIDStore interface, which
  # defines the necessary persistent state mechanisms. This library
  # comes bundled with serveral OpenIDStore implemetations.
  #
  # ==Stores
  #
  # The OpenID server needs to maintain state between requests in
  # order to function.  Its mechanism for doing this is called a
  # store.  The store interface is defined in OpenIDStore.
  # Additionally, several
  # concrete store implementations are provided, so that most sites
  # won't need to implement a custom store.  For a store backed by
  # flat files on disk, see FilesystemOpenIDStore.  For rails users
  # needing an SQL store, please see the ActiveRecord store in the 
  # examples directory.
  # 
  # ==Using this Library
  #
  # This library is designed to be easy to use for handling OpenID
  # requests.  There is, however, additional work a site has to do as
  # an OpenID server which is beyond the scope of this library.  That
  # work consists primarily of creating a couple additional pages for
  # handling verifying that the user wants to confirm their identity
  # to the consumer site.  Implementing an OpenID server using this
  # library should follow this basic plan:
  #
  # First, you need to choose a URL to be your OpenID server URL.
  # This URL needs to be able to handle both GET and POST requests,
  # and distinguish between them.
  #
  # Next, you need to have some system for mapping identity URLs to
  # users of your system.  The easiest method to do this is to insert
  # an appropriate <link> tag into your users' public pages.  See the
  # OpenID spec[http://openid.net/specs.bml#linkrel] for the
  # precise format the <link> tag needs to follow.  Then, each user's
  # public page URL is that user's identity URL.  There are many
  # alternative approaches, most of which should be fairly obvious.
  #
  # The next step is to write the code to handle requests to the
  # server URL.  When a request comes in, several steps need to take
  # place:
  #
  # 1. Get an OpenIDServer instance with an appropriate
  #    store.  This may be a previously created instance, or a new
  #    one, whichever is convenient for your application.
  #
  # 2. Call the OpenIDServer instance's get_openid_response
  #    method.  The first argument is a string indicating the HTTP
  #    method used to make the request.  This should be either
  #    'GET' or 'POST', the two HTTP methods that OpenID
  #    uses.  The second argument is the GET or POST (as
  #    appropriate) arguments provided for this request, parsed
  #    into a hash-like structure.  The third argument is a
  #    callback function for determining if authentication
  #    requests can proceed.  For more details on the callback
  #    function, see the the documentation for
  #    OpenIDServer.get_openid_response
  #
  # 3. The return value from that call is an array of two: [status, info].
  #    Depending on the status value returned, there are several
  #    different actions you might take.  See the documentation
  #    for the OpenIDServer.get_openid_response method for a full list
  #    of possible results, what they mean, and what the
  #    appropriate action for each is.
  #
  # Processing all the results from that last step is fairly simple,
  # but it involves adding a few additional pages to your site.  There
  # needs to be a page about OpenID that users who visit the server
  # URL directly can be shown, so they have some idea what the URL is
  # for.  It doesn't need to be a fancy page, but there should be one.
  #
  # Usually the OpenID::DO_AUTH case will also require at least one
  # page, and perhaps more.  These pages could be arranged many
  # different ways, depending on your site's policies on interacting
  # with its users.
  #
  # Overall, implementing an OpenID server is a fairly straightforward
  # process, but it requires significant application-specific work
  # above what this library provides.        
  #
  # ==OpenIDServer
  # 
  # This class is the interface to the OpenID server logic.  Instances
  # contain no per-request state, so a single instance can be reused
  # (or even used concurrently by multiple threads) as needed.
  #
  # This class presents an extremely high-level interface to the
  # OpenID server library via the get_openid_response method.
  class OpenIDServer
    
    @@SECRET_LIFETIME = 14 * 24 * 60 * 60 # 14 days
    @@SIGNED_FIELDS = ['mode', 'identity', 'return_to']

    # Creates a new OpenIDServer instance.
    # C{L{OpenIDServer}} instance contain no per-request internal
    # state, so they can be reused or used concurrently by multiple
    # threads, if desired.
    #
    # [+server_url+]
    #   The server's OpenID URL.  It is
    #   used whenever the server needs to generate a URL that will
    #   cause another OpenID request to be made, which can happen
    #   in authentication requests.  It's also used as part of the
    #   key for looking up and storing the server's secrets.
    #
    # [+store+]
    #   An object implementing the OpenIDStore interface which the library
    #   will use for persistent storage.  Please note that this may not be
    #   a "dumb" style store, it must be able to store association information.
    def initialize(server_url, store)
      raise ArgumentError("Server cannot use a dumb store") if store.dumb?

      @url = server_url
      @normal_key = @url + '|normal'
      @dumb_key = @url + '|dumb'
      @store = store
    end


    # get_openid_response processes an OpenID request, and determines the
    # proper way to respond.  It then communicates what that
    # response should be back to its caller via return codes.
    #
    # The return value of this method is an array, [status, info].
    # The first value is the status code describing what action
    # should be taken.  The second value is additional information
    # for taking that action, and varies based on the status.
    #
    # The following return codes are possible:
    #
    # 1. OpenID::REDIRECT - This code indicates that the server
    #    should respond with an HTTP redirect.  In this case,
    #    info is the URL to redirect the client to.
    #
    # 2. OpenID::DO_AUTH - This code indicates that the server
    #    should take whatever actions are necessary to allow
    #    this authentication to succeed or be cancelled, then
    #    try again.  In this case info is a
    #    AuthorizationInfo object, which contains additional
    #    useful information.
    #
    # 3. OpenID::DO_ABOUT - This code indicates that the server
    #    should display a page containing information about
    #    OpenID.  This is returned when it appears that a user
    #    entered an OpenID server URL directly in their
    #    browser, and the request wasn't an OpenID request at
    #    all.  In this case info is nil.
    #
    # 4. OpenID::REMOTE_OK - This code indicates that the server
    #    should return content verbatim in response to this
    #    request, with an HTTP status code of 200.  In this
    #    case, info is a String containing the content to
    #    return.
    #
    # 5. OpenID::REMOTE_ERROR - This code indicates that the
    #    server should return content verbatim in response to
    #    this request, with an HTTP status code of 400.  In
    #    this case, info is a String containing the content
    #    to return.
    #
    # 6. OpenID::LOCAL_ERROR - This code indicates an error that
    #    can't be handled within the protocol.  When this
    #    happens, the server may inform the user that an error
    #    has occured as it sees fit.  In this case, info is
    #    a short description of the error.
    #
    #
    # ===Paramters
    #
    # [+http_method+]
    #   String describing the HTTP method used to make the current request.
    #   The only expected values are 'GET' and 'POST'.  Case will be ignored.
    #
    # [+args+]
    #   Hash-like object that contains the unparsed, unescaped arguments that
    #   were sent with the OpenID request being handled.  The keys and values
    #   in the args hash should all be String objects.
    #
    # [+is_authorized+]
    #   Proc object that get_openid_response uses to determine whether or
    #   not this OpenID request should succeed. This callback needs to perform
    #   two tasks, and only evaluate to true if they both succeed, otherwise
    #   it should return false.
    #   
    #   The first task is to determine the user making this request, and
    #   if they are authorized to claim the identity URL passed into the
    #   block.  If the user making the request isn't authorized to claim the
    #   identity URL, the block should evaluate to false.
    #  
    #   The second task is to determine if the user will allow the trust_root
    #   in question to determine her identity.  If they have have not
    #   previously authorized the trust_root, then the block should evaluate
    #   to false.
    #
    #   If both above tasks evaluate to true, then the block should evaluate
    #   to true.
    #   
    #   An example:
    #
    #    is_authorized = Proc.new do |identity_url, trust_root|
    #      if logged_in? and (url_for_user == identity_url)
    #        trust_root_approved?(trust_root)
    #      else
    #        false
    #      end
    #    end
    def get_openid_response(http_method, args, is_authorized)
      http_method.upcase!

      case http_method
      when 'GET'
        trust_root = args['openid.trust_root']
        trust_root = args['openid.return_to'] if trust_root.nil?
        identity_url = args['openid.identity']
        if trust_root.nil? or identity_url.nil?
          authorized = false
        else
          authorized = is_authorized.call(identity_url, trust_root)
        end
        
        return get_auth_response(authorized, args)
        
      when 'POST'
        mode = args['openid.mode']

        if mode == 'associate'
          return associate(args)

        elsif mode == 'check_authentication'
          return check_authentication(args)

        else
          e = "Invalid openid.mode #{args['openid.mode']} for POST requests"
          return post_error(e)
        end

      else
        return [LOCAL_ERROR, "HTTP method #{http_method} not valid in OpenID"]
      end
    end

    protected

    def check_trust_root(args)
      return_to = args['openid.return_to']
      raise ArgumentError.new('no return_to specified') if return_to.nil?
      
      trust_root = args['openid.trust_root']

      # only check trust_root against return_to if one is given
      unless trust_root.nil?
        tr = OpenID::TrustRoot.parse(trust_root)
        
        if tr.nil?          
          raise ArgumentError, "Malformed trust root (#{trust_root})"
        end

        unless tr.validate_url(return_to)
          e = "return_to(#{return_to}) not valid" + \
          " against trust_root(#{trust_root})"
          raise ArgumentError, e
        end
      end

      return return_to
    end

    def get_auth_response(authorized, args)
      mode = args['openid.mode']
      
      unless ['checkid_immediate', 'checkid_setup'].member?(mode)
        e = "invalid openid.mode (#{mode}) for GET requests"
        return get_error(args, e)
      end

      identity = args['openid.identity']
      get_error(args, "No identity specified") if identity.nil?

      begin
        return_to = check_trust_root(args)
      rescue ArgumentError => e
        return get_error(args, e.to_s)
      end

      unless authorized
        if mode == 'checkid_immediate'
          nargs = args.dup
          nargs['openid.mode'] = 'checkid_setup'
          setup_url = OpenID::Util.append_args(@url, nargs)
          redirect_args = {
            'openid.mode' => 'id_res',
            'openid.user_setup_url' => setup_url
          }
          return [REDIRECT, OpenID::Util.append_args(return_to, redirect_args)]

        elsif mode == 'checkid_setup'
          return [DO_AUTH, AuthorizationInfo.new(@url, args)]

        else
          raise ArgumentError, "unable to handle openid.mode (#{mode})"
        end
      end

      reply = {
        'openid.mode' => 'id_res',
        'openid.return_to' => return_to,
        'openid.identity' => identity
      }
      
      assoc_handle = args['openid.assoc_handle']
      if assoc_handle.nil?
        assoc = create_association('HMAC-SHA1')
        @store.store_association(@dumb_key, assoc)
      else
        assoc = @store.get_association(@normal_key, assoc_handle)
        
        # fall back to dumb mode is assoc_handle not found
        if assoc.nil? or assoc.expired?
          unless assoc.nil?
            @store.remove_association(@normal_key, assoc.handle)
          end
          
          assoc = create_association('HMAC-SHA1')
          @store.store_association(@dumb_key, assoc)
          reply['openid.invalidate_handle'] = assoc_handle            
        end
      end

      reply['openid.assoc_handle'] = assoc.handle
      assoc.add_signature(@@SIGNED_FIELDS, reply)

      return [REDIRECT, OpenID::Util.append_args(return_to, reply)]
    end

    def associate(args)
      assoc_type = args.fetch('openid.assoc_type', 'HMAC-SHA1')
      assoc = create_association(assoc_type)
      
      if assoc.nil?
        e = "unable to create association for type #{assoc_type}"
        return post_error(e)
      else
        @store.store_association(@normal_key, assoc)
      end

      reply = {
        'assoc_type' => 'HMAC-SHA1',
        'assoc_handle' => assoc.handle,
        'expires_in' => assoc.expires_in.to_s
      }

      session_type = args['openid.session_type']
      unless session_type.nil?
        if session_type == 'DH-SHA1'
          modulus = args['openid.dh_modulus']
          generator = args['openid.dh_gen']
          
          begin
            dh = OpenID::DiffieHellman.from_base64(modulus, generator)
          rescue
            e = "Please convert to two's comp correctly"
            return post_error(e)
          end

          consumer_public = args['openid.dh_consumer_public']
          if consumer_public.nil?
            return post_error('Missing openid.dh_consumer_public')
          end

          cpub = OpenID::Util.base64_to_num(consumer_public)
          if cpub < 0
            return post_error("Please convert to two's comp correctly")
          end
          
          dh_server_public = OpenID::Util.num_to_base64(dh.public)
          mac_key = dh.xor_secrect(cpub, assoc.secret)
          reply['session_type'] = session_type
          reply['dh_server_public'] = dh_server_public
          reply['enc_mac_key'] = OpenID::Util.to_base64(mac_key)
        else
          return post_error('session_type must be DH-SHA1')
        end
      else
        reply['mac_key'] = OpenID::Util.to_base64(assoc.secret)
      end

      return [REMOTE_OK, OpenID::Util.kvform(reply)]
    end

    def check_authentication(args)
      assoc_handle = args['openid.assoc_handle']
      
      if assoc_handle.nil?
        return post_error('Missing openid.assoc_handle')
      end

      assoc = @store.get_association(@dumb_key, assoc_handle)
      
      reply = {}
      if (not assoc.nil?) and assoc.expires_in > 0
        signed = args['openid.signed']
        return post_error('Missing openid.signed') if signed.nil?

        sig = args['openid.sig']
        return post_error('Missing openid.sig') if sig.nil?

        to_verify = args.dup
        to_verify['openid.mode'] = 'id_res'

        signed_fields = signed.strip.split(',')
        tv_sig = assoc.sign_hash(signed_fields, to_verify)
        
        if tv_sig == sig
          @store.remove_association(@normal_key, assoc_handle)
          is_valid = 'true'

          invalidate_handle = args['openid.invalidate_handle']
          unless invalidate_handle.nil?
            a = @store.get_association(@normal_key, invalidate_handle)
            reply['invalidate_handle'] = invalidate_handle if a.nil?
          end
          
        else
          is_valid = 'false'
        end
        
      else
        @store.remove_association(@dumb_key, assoc_handle) unless assoc.nil?
        is_valid = 'false'
      end
      
      reply['is_valid'] = is_valid
      return [REMOTE_OK, OpenID::Util.kvform(reply)]
    end

    def create_association(assoc_type)
      return nil unless assoc_type == 'HMAC-SHA1'
      
      secret = OpenID::Util.get_random_bytes(20)
      uniq = OpenID::Util.to_base64(OpenID::Util.get_random_bytes(4))
      handle = "{%s}}{%x}{%s}" % [assoc_type, Time.now.to_i, uniq]
      assoc = Association.from_expires_in(@@SECRET_LIFETIME,
                                          handle,
                                          secret,
                                          assoc_type)
      return assoc
                                          
    end

    def get_error(args, msg)
      return_to = args['openid.return_to']
      unless return_to.nil?
        err = {
          'openid.mode' => 'error',
          'openid.error' => msg
        }
        return [REDIRECT, OpenID::Util.append_args(return_to, err)]
      else
        args.each do |k,v|
          return [LOCAL_ERROR, msg] if k.index('openid.') == 0
        end
        
        return [DO_ABOUT, nil]
      end
    end

    def post_error(msg)
      return [REMOTE_ERROR, OpenID::Util.kvform({'error'=>msg})]
    end
    

  end

  # This is a class to encapsulate information that is useful when
  # interacting with a user to determine if an authentication request
  # can be authorized to succeed.  This class provides methods to get
  # the identity URL and trust root from the request that failed.
  # Given those, the server can determine what needs to happen in
  # order to allow the request to proceed, and can ask the user to
  # perform the necessary actions.
  #
  # The user may choose to either perform the actions or not.  If they
  # do, the server should try to perform the request OpenID request
  # again.  If they choose not to, and inform the server by hitting
  # some form of cancel button, the server should redirect them back
  # to the consumer with a notification of that for the consumer.
  #
  # This class provides two approaches for each of those actions.  The
  # server can either send the user redirects which will cause the
  # user to retry the OpenID request, or it can help perform those
  # actions without involving an extra redirect, producing output that
  # works like that of OpenIDServer.get_openid_response.
  #
  # Both approaches work equally well, and you should choose the one
  # that fits into your framework better.
  #
  # The AuthorizationInfo.retry and AuthorizationInfo.cancel methods produce
  # [status,info] arrays that should be handled exactly like the responses
  # from OpenIDServer.get_openid_response.
  #
  # The retry_url and cancel_url attributes return URLs
  # to which the user can be redirected to automatically retry or
  # cancel this OpenID request.
  class AuthorizationInfo

    attr_reader :cancel_url, :identity_url, :trust_root, :return_to
    
    # creates a new AuthorizationInfo object for the
    # given values.  AuthorizationInfo objects are generated by the various
    # methods in OpenIDServer, and should not be created directly by the user.
    def initialize(server_url, args)
      @server_url = server_url
      @return_to = args['openid.return_to']
      @identity_url = args['openid.identity']
      @trust_root = args['openid.trust_root'] or @return_to
      
      cancel_args = {'openid.mode' => 'cancel'}
      @cancel_url = OpenID::Util.append_args(@return_to, cancel_args)
      @args = args.dup
    end

    # Retries an OpenID authentication request.  Basically just calls
    # OpenIDServer instance passed in with its request arguments,
    # and the is_authorized Proc passed in.
    def retry(openid_server, is_authorized)      
      openid_server.get_openid_response('GET', @args, is_authorized)
    end

    # Cancels an OpenID request
    def cancel
      return [REDIRECT, @cancel_url]
    end

    def retry_url
      OpenID::Util.append_args(@server_url, @args)
    end

    # Generate a string representing this object. The string can be
    # passed into the AuthorizationInfo.deserialize class method to
    # recreate the instance.
    def serialize
      @server_url + '|' + OpenID::Util.urlencode(@args)
    end

    def AuthorizationInfo.deserialize(s)
      server_url, string_args = s.split('|', 2)
      args = {}
      CGI::parse(string_args).each {|k,vals| args[k] = vals[0]}
      return new(server_url, args)
    end

    def ==(other)
      self.instance_variable_hash == other.instance_variable_hash
    end

  end

end
