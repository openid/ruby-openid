module OpenID
  class SessionProxy
    # Public: initailize the Proxy instance
    #
    # session - Session for storage
    # klass - Class to encode/decode
    #
    # Returns the proxy instance
    def initialize(session, klass)
      @session = session
      @klass = klass
    end

    def [](key)
      value = @session[key]
      if @klass.respond_to?(:session_decode)
        @klass.session_decode(value)
      else
        value
      end
    end

    def []=(key, value)
      @session[key] = encode(value)
    end

    private

    def encode(obj)
      case obj
      when Array
        obj.collect { |ele| encode(ele) }
      when Hash
        Hash[ config.collect { |k,v| [k, encode(v)] } ]
      else
        obj.respond_to?(:session_encode) ? obj.session_encode : obj
      end
    end
  end
end
