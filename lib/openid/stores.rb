require "openid/util"

module OpenID

  # Interface for the abstract OpenIDStore
  class OpenIDStore

    @@AUTH_KEY_LEN = 20

    # Put a Association object into storace
    def store_association(association)
      raise NotImplementedError
    end

    # Returns a Association object from storage that matches
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
