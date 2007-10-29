require "openid/message"
require "openid/fetchers"
require "openid/dh"
require "openid/util"
require "openid/cryptutil"


module OpenID

  # Exception that is raised when the server returns a 400 response
  # code to a direct request.
  class ServerError < Exception
    attr_reader :error_text, :error_code, :message

    def initialize(error_text, error_code, message)
      super(error_text)
      @error_text = error_text
      @error_code = error_code
      @message = message
    end
  end

  class Message
    def self.from_http_response(response, server_url)
      msg = self.from_kvform(response.body)
      case response.status
      when 200
        return msg
      when 400
        error_text = msg.get_arg(OPENID_NS, 'error',
                                 '<no error message supplied>')
        error_code = msg.get_arg(OPENID_NS, 'error_code')
        raise ServerError.new(error_text, error_code, msg)
      else
        error_message = "bad status code from server #{server_url}: "\
          "#{response.status}"
        raise StandardError.new(error_message)
      end
    end
  end

  # Send the message to the server via HTTP POST and receive and parse
  # a response in KV Form
  def self.make_kv_post(request_message, server_url)
    http_response = self.fetch(server_url, request_message.to_url_encoded)
    return Message.from_http_response(http_response, server_url)
  end

  class Consumer
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

      def get_request
        args = {'dh_consumer_public' => CryptUtil.num_to_base64(@dh.public)}
        if (!@dh.using_default_values?)
          args['dh_modulus'] = CryptUtil.num_to_base64(@dh.modulus)
          args['dh_gen'] = CryptUtil.num_to_base64(@dh.generator)
        end

        return args
      end

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

    class DiffieHellmanSHA1Session < DiffieHellmanSession
      @session_type = 'DH-SHA1'
      @secret_size = 20
      @allowed_assoc_types = ['HMAC-SHA1']
      @hashfunc = CryptUtil.method(:sha1)
    end

    class DiffieHellmanSHA256Session < DiffieHellmanSession
      @session_type = 'DH-SHA256'
      @secret_size = 32
      @allowed_assoc_types = ['HMAC-SHA256']
      @hashfunc = CryptUtil.method(:sha256)
    end

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
