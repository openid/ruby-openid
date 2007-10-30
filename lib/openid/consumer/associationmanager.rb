require "openid/util"
require "openid/kvpost"
require "openid/cryptutil"

module OpenID
  class Consumer

    # A superclass for implementing Diffie-Hellman association sessions.
    class DiffieHellmanSession
      class << self
        attr_reader :session_type, :secret_size, :allowed_assoc_types,
          :hashfunc
      end

      def initialize(dh=nil)
        if dh.nil?
          dh = DiffieHellman.from_defaults
        end
        @dh = dh
      end

      # Return the query parameters for requesting an association
      # using this Diffie-Hellman association session
      def get_request
        args = {'dh_consumer_public' => CryptUtil.num_to_base64(@dh.public)}
        if (!@dh.using_default_values?)
          args['dh_modulus'] = CryptUtil.num_to_base64(@dh.modulus)
          args['dh_gen'] = CryptUtil.num_to_base64(@dh.generator)
        end

        return args
      end

      # Process the response from a successful association request and
      # return the shared secret for this association
      def extract_secret(response)
        dh_server_public64 = response.get_arg(OPENID_NS, 'dh_server_public',
                                              NO_DEFAULT)
        enc_mac_key64 = response.get_arg(OPENID_NS, 'enc_mac_key', NO_DEFAULT)
        dh_server_public = CryptUtil.base64_to_num(dh_server_public64)
        enc_mac_key = Util.from_base64(enc_mac_key64)
        return @dh.xor_secret(self.class.hashfunc,
                              dh_server_public, enc_mac_key)
      end
    end

    # A Diffie-Hellman association session that uses SHA1 as its hash
    # function
    class DiffieHellmanSHA1Session < DiffieHellmanSession
      @session_type = 'DH-SHA1'
      @secret_size = 20
      @allowed_assoc_types = ['HMAC-SHA1']
      @hashfunc = CryptUtil.method(:sha1)
    end

    # A Diffie-Hellman association session that uses SHA256 as its hash
    # function
    class DiffieHellmanSHA256Session < DiffieHellmanSession
      @session_type = 'DH-SHA256'
      @secret_size = 32
      @allowed_assoc_types = ['HMAC-SHA256']
      @hashfunc = CryptUtil.method(:sha256)
    end

    # An association session that does not use encryption
    class NoEncryptionSession
      class << self
        attr_reader :session_type, :allowed_assoc_types
      end
      @session_type = 'no-encryption'
      @allowed_assoc_types = ['HMAC-SHA1', 'HMAC-SHA256']

      def get_request
        return {}
      end

      def extract_secret(response)
        mac_key64 = response.get_arg(OPENID_NS, 'mac_key', NO_DEFAULT)
        return Util.from_base64(mac_key64)
      end
    end
  end
end
