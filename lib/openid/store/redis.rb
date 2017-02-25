require 'openid/util'
require 'openid/store/interface'
require 'openid/store/nonce'
require 'time'

module OpenID
  module Store
    class Redis < Interface
      attr_reader :key_prefix

      def initialize(redis_client = ::Redis.current, key_prefix = 'openid-store:')
        @redis_client = redis_client
        @key_prefix   = key_prefix
      end

      def store_association(server_url, association)
        serialized = serialize(association)

        [nil, association.handle].each do |handle|
          key = assoc_key(server_url, handle)

          @redis_client.setex(key, association.lifetime, serialized)
        end
      end

      def get_association(server_url, handle = nil)
        serialized = @redis_client.get(assoc_key(server_url, handle))

        deserialize(serialized) if serialized
      end

      def remove_association(server_url, handle)
        deleted = delete(assoc_key(server_url, handle))
        server_assoc = get_association(server_url)

        if server_assoc && server_assoc.handle == handle
          deleted = delete(assoc_key(server_url)) | deleted
        end

        deleted
      end

      def use_nonce(server_url, timestamp, salt)
        return false if (timestamp - Time.now.to_i).abs > Nonce.skew

        nonce_key = key_prefix + 'N' + server_url + '|' + timestamp.to_s + '|' + salt

        return false if @redis_client.exists(nonce_key)

        @redis_client.setex(nonce_key, Nonce.skew + 5, "")

        true
      end

      def assoc_key(server_url, assoc_handle = nil)
        key = key_prefix + 'A' + server_url

        if assoc_handle
          key += '|' + assoc_handle
        end

        key
      end

      def cleanup_nonces
      end

      def cleanup
      end

      def cleanup_associations
      end

      protected

      def delete(key)
        !@redis_client.del(key).zero?
      end

      def serialize(assoc)
        Marshal.dump(assoc)
      end

      def deserialize(assoc_str)
        Marshal.load(assoc_str)
      end
    end
  end
end
