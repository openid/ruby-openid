require "openid/util"

module OpenID

  # Consumer's view of an association with a server
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

    def ConsumerAssociation.from_expires_in(expires_in, server_url,
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
        OpenID::Util.to_base64(assoc.secret),
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
  
      secret = OpenID::Util.from_base64(secret)
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

    def expires_in
      [0, @issued + @lifetime - Time.now.to_i].max
    end

    def expired?
      return expires_in == 0
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
    def store_association(association)
      raise NotImplementedError
    end

    # Returns a ConsumerAssociation object from storage that matches
    # the server_url.  Returns nil if no such association is found or if
    # the one matching association is expired. (Is allowed to GC expired
    # associations when found.)
    def get_association(server_url)
      raise NotImplementedError
    end

    # If there is a matching association, remove it from the store and
    # return true, otherwise return false.
    def removeAssociation(server_url, handle)
      raise NotImplementedError
    end

    # Stores a nonce (which is passed in as a string).
    def store_nonce(nonce)
      raise NotImplementedError
    end

    # If the nonce is in the store, remove it and return true. Otherwise
    # return false.
    def use_nonce(nonce)
      raise NotImplementedError
    end

    # Returns a 20-byte auth key used to sign the tokens, to ensure
    # that they haven't been tampered with in transit. It must return
    # the same key every time it is called.   
    def get_auth_key
      raise NotImplementedError
    end

    # Method return true if the store is dumb-mode-style store.
    def dumb?
      false
    end

  end


  class DumbStore < OpenIDStore
    
    def initialize(secret_phrase)
      require "digest/sha1"
      @auth_key = Digest::SHA1.hexdigest(secret_phrase)
    end

    def store_association(assoc)
      nil
    end

    def get_association(server_url)
      nil
    end
  
    def removeAssociation(server_url, handle)
      false
    end

    def store_nonce(nonce)
      nil
    end

    def use_nonce(nonce)
      true
    end

    def get_auth_key
      @auth_key
    end

    def dumb?
      true
    end

  end

end
