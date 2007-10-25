require "openid/kvform"
require "openid/util"

module OpenID
  class Association
    attr_reader :handle, :secret, :issued, :lifetime, :assoc_type

    def initialize(handle, secret, issued, lifetime, assoc_type)
      @handle = handle
      @secret = secret
      @issued = issued
      @lifetime = lifetime
      @assoc_type = assoc_type
    end

    def serialize
      data = {
        :version => '2',
        :handle => handle,
        :secret => Util.to_base64(secret),
        :issued => issued.to_i.to_s,
        :lifetime => lifetime.to_i.to_s,
        :assoc_type => assoc_type,
      }

      Util.assert(data.length == FIELD_ORDER.length)

      pairs = FIELD_ORDER.map{|field| [field.to_s, data[field]]}
      return Util.seq_to_kv(pairs, strict=true)
    end

    def Association.deserialize(serialized)
      parsed = Util.kv_to_seq(serialized)
      parsed_fields = parsed.map{|k, v| k.to_sym}
      if parsed_fields != FIELD_ORDER
          raise StandardError, 'Unexpected fields in serialized association'\
          " (Expected #{FIELD_ORDER.inspect}, got #{parsed_fields.inspect})"
      end
      version, handle, secret64, issued_s, lifetime_s, assoc_type =
        parsed.map {|field, value| value}
      if version != '2'
        raise StandardError, "Attempted to deserialize unsupported version "\
                             "(#{parsed[0][1].inspect})"
      end

      Association.new(handle,
                      Util.from_base64(secret64),
                      Time.at(issued_s.to_i),
                      lifetime_s.to_i,
                      assoc_type)
    end

    private
    FIELD_ORDER =
      [:version, :handle, :secret, :issued, :lifetime, :assoc_type,]

  end
end
