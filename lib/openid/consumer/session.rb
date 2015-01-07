module OpenID
  class Consumer
    class Session
      def initialize(session, decode_klass = nil)
        @session = session
        @decode_klass = decode_klass
      end

      def [](key)
        val = @session[key]
        @decode_klass ? @decode_klass.from_session_value(val) : val
      end

      def []=(key, val)
        @session[key] = to_session_value(val)
      end

      def keys
        @session.keys
      end

      private

      def to_session_value(val)
        case val
        when Array
          val.map{|ele| to_session_value(ele) }
        when Hash
          Hash[*(val.map{|k,v| [k, to_session_value(v)] }.flatten(1))]
        else
          val.respond_to?(:to_session_value) ? val.to_session_value : val
        end
      end
    end
  end
end
