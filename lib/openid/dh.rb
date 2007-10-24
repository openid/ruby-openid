require "openid/util"

module OpenID

  # Encapsulates a Diffie-Hellman key exchange.  This class is used
  # internally by both the consumer and server objects.
  #
  # Read more about Diffie-Hellman on wikipedia:
  # http://en.wikipedia.org/wiki/Diffie-Hellman

  class DiffieHellman

    @@DEFAULT_MOD = 155172898181473697471232257763715539915724801966915404479707795314057629378541917580651227423698188993727816152646631438561595825688188889951272158842675419950341258706556549803580104870537681476726513255747040765857479291291572334510643245094715007229621094194349783925984760375594985848253359305585439638443
    @@DEFAULT_GEN = 2

    attr_reader :p, :g, :public

    def DiffieHellman.from_defaults
      DiffieHellman.new(DiffieHellman.DEFAULT_GEN, DiffieHellman.DEFAULT_MOD)
    end

    def initialize(p=nil, g=nil)
      @p = p.nil? ? @@DEFAULT_MOD : p
      @g = g.nil? ? @@DEFAULT_GEN : g

      @private = OpenID::CryptUtil.rand(@p-2) + 1
      @public = OpenID::CryptUtil.powermod(@g, @private, @p)
    end

    def get_shared_secret(composite)
      OpenID::CryptUtil.powermod(composite, @private, @p)
    end

    def xor_secrect(algorithm, composite, secret)
      dh_shared = get_shared_secret(composite)
      packed_dh_shared = OpenID::CryptUtil.num_to_str(dh_shared)
      hashed_dh_shared = algorithm.call(packed_dh_shared)
      return strxor(secret, hashed_dh_shared)
    end

    private
    def DiffieHellman.strxor(s, t)
      if s.length != t.length
        raise ArgumentError, "strxor: lengths don't match. " +
          "Inputs were #{s.inspect} and #{t.inspect}"
      end

      indices = 0...(s.length)
      chrs = indices.collect {|i| (s[i]^t[i]).chr}
      chrs.join("")
    end

  end

end
