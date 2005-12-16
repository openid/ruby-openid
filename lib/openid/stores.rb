require "openid/util"

# Consumer's view of an association

module OpenID

  class ConsumerAssociation

    @@assoc_keys = [
      'version',
      'server_url',
      'handle',
      'secret',
      'issued',
      'lifetime'
    ]

    attr_reader :server_url, :handle, :secret, :issued, :lifetime

    def ConsumerAssociation.fromExpiresIn(expires_in, server_url,
                                          handle, secret)
      issued = Time.now.to_i
      lifetime = expires_in
      new(server_url, handle, secret, issued, lifetime) 
    end

    def ConsumerAssociation.serialize(assoc)
      data = [
        '1',
        assoc.server_url,
        assoc.handle,
        OpenID::Util.toBase64(assoc.secret),
        assoc.issued.to_i.to_s,
        assoc.lifetime.to_i.to_s
      ]
  
      lines = ""
      (0...@@assoc_keys.length).collect do |i| 
        lines += "#{@@assoc_keys[i]}: #{data[i]}\n"
      end
    
      lines
    end

    def ConsumerAssociation.deserialize(assoc_s)
      keys = []
      values = []
      assoc_s.split("\n").each do |line|
        k, v = line.split(":", 2)
        keys << k.strip
        values << v.strip
      end
  
      version, server_url, handle, secret, issued, lifetime = values
      raise 'VersionError' if version != '1'
  
      secret = OpenID::Util.fromBase64(secret)
      issued = issued.to_i
      lifetime = lifetime.to_i
      ConsumerAssociation.new(server_url, handle, secret, issued, lifetime)
    end

    def initialize(server_url, handle, secret, issued, lifetime)
      @server_url = server_url
      @handle = handle
      @secret = secret
      @issued = issued
      @lifetime = lifetime
    end

    def expiresIn
      [0, @issued + @lifetime - Time.now.to_i].max
    end

    def ==(other)    
      def iv_values(o)
        o.instance_variables.collect {|i| o.instance_variable_get(i)}
      end  
      iv_values(self) == iv_values(other)
    end

  end


  # Interface for the abstract OpenIDStore

  class OpenIDStore

    @@AUTH_KEY_LEN = 20

    # Put a ConsumerAssociation object into storace

    def storeAssociation(association)
      raise NotImplementedError
    end

    # Returns a ConsumerAssociation object from storage that matches
    # the server_url.  Returns nil if no such association is found or if
    # the one matching association is expired. (Is allowed to GC expired
    # associations when found.)

    def getAssociation(server_url)
      raise NotImplementedError
    end

    # If there is a matching association, remove it from the store and
    # return true, otherwise return false.

    def removeAssociation(server_url, handle)
      raise NotImplementedError
    end

    # Stores a nonce (which is passed in as a string).

    def storeNonce(nonce)
      raise NotImplementedError
    end

    # If the nonce is in the store, remove it and return true. Otherwise
    # return false.

    def useNonce(nonce)
      raise NotImplementedError
    end

    # Returns a 20-byte auth key used to sign the tokens, to ensure
    # that they haven't been tampered with in transit. It must return
    # the same key every time it is called.
    
    def getAuthKey
      raise NotImplementedError
    end

    # Method return true if the store is dumb-mode-style store.

    def isDumb?
      false
    end

  end


  class DumbStore < OpenIDStore
    
    def initialize(secret_phrase)
      require "digest/sha1"
      @auth_key = Digest::SHA1.hexdigest(secret_phrase)
    end

    def storeAssociation(assoc)
      nil
    end

    def getAssociation(server_url)
      nil
    end
  
    def removeAssociation(server_url, handle)
      false
    end

    def storeNonce(nonce)
      nil
    end

    def useNonce(nonce)
      true
    end

    def getAuthKey
      @auth_key
    end

    def isDumb?
      true
    end

  end

end
