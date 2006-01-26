require 'cgi'

require 'openid/util'
require 'openid/dh'
require 'openid/trustroot'

module OpenID

  REDIRECT     = 'redirect'
  DO_AUTH      = 'do_auth'
  DO_ABOUT     = 'do_about'
  
  REMOTE_OK    = 'exact_ok'
  REMOTE_ERROR = 'exact_error'
  
  LOCAL_ERROR  = 'local_error'

  class OpenIDServer
    
    @@SECRET_LIFETIME = 14 * 24 * 60 * 60 # 14 days
    @@SIGNED_FIELDS = ['mode', 'identity', 'return_to']

    def initialize(server_url, store)
      raise ArgumentError("Server cannot use a dumb store") if store.dumb?

      @url = server_url
      @normal_key = @url + '|normal'
      @dumb_key = @url + '|dumb'
      @store = store
    end

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

    
  class AuthorizationInfo

    def initialize(server_url, args)
      # XXX: raise ArgumentError is there is not return_to or other 
      # XXX: openid attrs?

      @server_url = server_url
      @return_to = args['openid.return_to']
      @identity_url = args['openid.identity']
      @trust_root = args['openid.trust_root'] or @return_to
      
      cancel_args = {'openid.mode' => 'cancel'}
      @cancel_url = OpenID::Util.append_args(@return_to, cancel_args)
      @args = args.dup
    end

    def retry(openid_server, is_authorized)
      openid_server.get_openid_response('GET', @args, is_authorized)
    end

    def cancel
      return [REDIRECT, @cancel_url]
    end

    def get_retry_url
      OpenID::Util.append_args(@server_url, @args)
    end

    def get_cancel_url
      @cancel_url
    end

    def get_identity_url
      @identity_url
    end

    def get_trust_root
      @trust_root
    end

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
