#
#  The OpenIDConsumer interface follows the python library API exactly. Please
#  use the Python API docs until they are ported to Ruby.  Also see
#  examples/consumer.rb for a real conusmer example that uses this api.
#
#  http://www.openidenabled.com/resources/docs/openid/python/1.0.1/openid.consumer.consumer-module.html
#
#  You should only need to use the public API calls: beginAuth, constructRedirect, and completeAuth.
#
#  More ruby-specific docs are on the way.  


require "uri"

require "openid/util"
require "openid/dh"
require "openid/parse"
require "openid/fetchers"

module OpenID

  SUCCESS = 'success'
  FAILURE = 'failure'
  SETUP_NEEDED = 'setup needed'  
  HTTP_FAILURE = 'http failure'
  PARSE_ERROR = 'parse error'

  class OpenIDConsumer

    @@NONCE_LEN = 8
    @@NONCE_CHRS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    @@TOKEN_LIFETIME = 60 * 2 # two minutes
    

    #####################################################################
    #
    # Begin public API.  
    #
    #####################################################################
    public

    def initialize(store, fetcher=nil, immediate=false)
      if fetcher.nil?
        fetcher = NetHTTPFetcher.new
      end

      @store = store
      @fetcher = fetcher
      @immediate = immediate
      @mode = immediate ? "checkid_immediate" : "checkid_setup"
    end

    def beginAuth(user_url)
      status, info = self.findIdentityInfo(user_url)
      return [status, info] if status != SUCCESS
    
      consumer_id, server_id, server_url = info
      nonce = OpenID::Util.randomString(@@NONCE_LEN, @@NONCE_CHRS)
      @store.storeNonce(nonce)
    
      token = self.genToken(nonce, consumer_id, server_id, server_url)
      [SUCCESS, OpenIDAuthRequest.new(token, server_id, server_url, nonce)]
    end
    
    def constructRedirect(auth_req, return_to, trust_root)
      redir_args = {
        "openid.identity" => auth_req.server_id,
        "openid.return_to" => return_to,
        "openid.trust_root" => trust_root,
        "openid.mode" => @mode
      }

      assoc = self.getAssociation(auth_req.server_url)
      redir_args["openid.assoc_handle"] = assoc.handle unless assoc.nil?

      OpenID::Util.appendArgs(auth_req.server_url, redir_args).to_s
    end

    def completeAuth(token, query)
      mode = query["openid.mode"]
      case mode
      when "cancel"
        return [SUCCESS, nil]
      when "error"
        error = query["openid.error"]
        unless error.nil?
          OpenID::Util.log('Error: '+error)
        end
        return [FAILURE, nil]
      when "id_res"
        return self.doIdRes(token, query)
      else
        return [FAILURE, nil]
      end
    end

    #####################################################################
    #
    # End public API.  Methods below are for internal use.
    #
    #####################################################################
    protected

    def doIdRes(token, query)
      ret = self.splitToken(token)
      return [FAILURE, nil] if ret.nil?
      
      nonce, consumer_id, server_id, server_url = ret
      
      return_to = query["openid.return_to"]
      server_id2 = query["openid.identity"]
      assoc_handle = query["openid.assoc_handle"]
      
      if return_to.nil? or server_id.nil? or assoc_handle.nil?
        return [FAILURE, consumer_id]
      end

      if server_id != server_id2
        return [FAILURE, consumer_id]
      end

      user_setup_url = query["openid.user_setup_url"]
      unless user_setup_url.nil?
        return [SETUP_NEEDED, user_setup_url]
      end
      
      assoc = @store.getAssociation(server_url)
    
      if assoc.nil? or assoc.handle != assoc_handle or assoc.expiresIn <= 0
        # It's not an associtaion we know about.  Dumb mode is our only recovery
        check_args = OpenID::Util.getOpenIDParameters(query)
        check_args["openid.mode"] = "check_authentication"
        post_data = OpenID::Util.urlencode(check_args)
        return self.checkAuth(nonce, consumer_id, post_data, server_url)
      end

      # Check the signature
      sig = query["openid.sig"]
      signed = query["openid.signed"]
      return [FAILURE, consumer_id] if sig.nil? or signed.nil?
      
      args = OpenID::Util.getOpenIDParameters(query)
      signed_list = signed.split(",")
      _signed, v_sig = OpenID::Util.signReply(args, assoc.secret, signed_list)
      
      return [FAILURE, consumer_id] if v_sig != sig    
      return [FAILURE, consumer_id] unless @store.useNonce(nonce)
      return [SUCCESS, consumer_id]
    end

    def checkAuth(nonce, consumer_id, post_data, server_url)
      ret = @fetcher.post(server_url, post_data)
      if ret.nil?
        return [FAILURE, consumer_id]
      else
        url, body = ret
      end
    
      results = OpenID::Util.parsekv(body)
      is_valid = results.fetch("is_valid", "false")
    
      if is_valid == "true"
        invalidate_handle = results["invalidate_handle"]
        unless invalidate_handle.nil?
          @store.removeAssociation(server_url, invalidate_handle)
        end
        unless @store.useNonce(nonce)
          return [FAILURE, consumer_id]
        end
        return [SUCCESS, consumer_id]
      end
    
      error = results["error"]
      return [FAILURE, consumer_id] unless error.nil?
      return [FAILURE, consumer_id]
    end

    def getAssociation(server_url)
      return nil if @store.isDumb?
      assoc = @store.getAssociation(server_url)
      return assoc unless assoc.nil?
      return self.associate(server_url)    
    end
    
    def genToken(nonce, consumer_id, server_id, server_url)
      timestamp = Time.now.to_i.to_s
      joined = [timestamp, nonce, consumer_id,
                server_id, server_url].join("\x00")
      sig = OpenID::Util.hmacSha1(@store.getAuthKey, joined)
      OpenID::Util.toBase64(sig+joined)
    end

    def splitToken(token)
      token = OpenID::Util.fromBase64(token)
      return nil if token.length < 20
      
      sig, joined = token[(0...20)], token[(20...token.length)]
      return nil if OpenID::Util.hmacSha1(@store.getAuthKey, joined) != sig
      
      s = joined.split("\x00")
      return nil if s.length != 5

      timestamp, nonce, consumer_id, server_id, server_url = s
      
      timestamp = timestamp.to_i
      return nil if timestamp == 0
      return nil if (timestamp + @@TOKEN_LIFETIME) < Time.now.to_i
      
      return [nonce, consumer_id, server_id, server_url].freeze
    end

    def normalizeURL(url)
      url.strip!
      parsed = URI.parse(url)
      parsed = URI.parse("http://"+url) if parsed.scheme.nil?
      parsed.normalize!
      parsed.to_s
    end

    def findIdentityInfo(identity_url)
      url = self.normalizeURL(identity_url)
      ret = @fetcher.get(url)
      return [HTTP_FAILURE, nil] if ret.nil?
      
      consumer_id, data = ret
      server = nil
      delegate = nil
      parseLinkAttrs(data) do |attrs|
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

      consumer_id = self.normalizeURL(consumer_id)
      server_id = self.normalizeURL(server_id)
      server = self.normalizeURL(server)
      
      return [SUCCESS, [consumer_id, server_id, server].freeze]
    end
    
    def associate(server_url)
      dh = OpenID::DiffieHellman.new
      cpub = OpenID::Util.toBase64(OpenID::Util.numToStr(dh.public))
      args = {
        'openid.mode' => 'associate',
        'openid.assoc_type' =>'HMAC-SHA1',
        'openid.session_type' =>'DH-SHA1',
        'openid.dh_modulus' => OpenID::Util.toBase64(OpenID::Util.numToStr(dh.p)),
        'openid.dh_gen' => OpenID::Util.toBase64(OpenID::Util.numToStr(dh.g)),
        'openid.dh_consumer_public' => cpub
      }
      body = OpenID::Util.urlencode(args)
      
      ret = @fetcher.post(server_url, body)
      return nil if ret.nil?
      url, data = ret
      results = OpenID::Util.parsekv(data)
      
      assoc_type = results["assoc_type"]
      return nil if assoc_type.nil? or assoc_type != "HMAC-SHA1"
      
      assoc_handle = results["assoc_handle"]
      return nil if assoc_handle.nil?    
      
      expires_in = results.fetch("expires_in", "0").to_i

      session_type = results["session_type"]
      if session_type.nil?
        secret = OpenID::Util.fromBase64(results["mac_key"])
      else
        return nil if session_type != "DH-SHA1"
        
        dh_server_public = results["dh_server_public"]
        return nil if dh_server_public.nil?
        
        spub = OpenID::Util.strToNum(OpenID::Util.fromBase64(dh_server_public))
        dh_shared = dh.getSharedSecret(spub)
        enc_mac_key = results["enc_mac_key"]
        secret = OpenID::Util.strxor(OpenID::Util.fromBase64(enc_mac_key),
                                     OpenID::Util.sha1(OpenID::Util.numToStr(dh_shared)))
      end
   
      assoc = OpenID::ConsumerAssociation.fromExpiresIn(expires_in, server_url,
                                                        assoc_handle, secret)
      @store.storeAssociation(assoc)
      assoc
    end

  end

  class OpenIDAuthRequest
    
    attr_reader :token, :server_id, :server_url, :nonce
    
    # Creates a new OpenIDAuthRequest object.  This just stores each
    # argument in an appropriately named field.
    #
    # Users of this library should not create instances of this
    # class.  Instances of this class are created by the library
    # when needed.
    
    def initialize(token, server_id, server_url, nonce)
      @token = token
      @server_id = server_id
      @server_url = server_url
      @nonce = nonce
    end

  end
  
end
