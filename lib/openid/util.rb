require "base64"
require "cgi"
require "digest/sha1"
require "hmac-sha1"

srand(Time.now.to_f)

module OpenID

  module Util

    HAS_URANDOM = File.chardev? '/dev/urandom'

    def Util.getOpenIDParameters(query)
      params = {}
      query.each do |k,v|
        params[k] = v if k.index("openid.") == 0
      end
      params
    end

    def Util.hmacSha1(key, text)
      HMAC::SHA1.digest(key, text)
    end

    def Util.sha1(s)
      Digest::SHA1.digest(s)
    end
   
    def Util.toBase64(s)
      Base64.encode64(s).gsub("\n", "")
    end

    def Util.fromBase64(s)
      Base64.decode64(s)
    end
 
    def Util.kvForm(hash)
      form = ""
      hash.each do |k,v|
        form << "#{k}:#{v}\n"
      end
      form
    end

    def Util.parsekv(s)
      s.strip!
      form = {}
      s.split("\n").each do |line|
        pair = line.split(":", 2)
        if pair.length == 2
          k, v = pair
          form[k.strip] = v.strip
        end
      end
      form
    end

    def Util.numToStr(n)
      # taken from openid-ruby 0.0.1
      bits = n.to_s(2)
      prepend = (8 - bits.length % 8) || (bits.index(/^1/) ? 8 : 0)
      bits = ('0' * prepend) + bits if prepend
      [bits].pack('B*')
    end

    def Util.strToNum(s)
      # taken from openid-ruby 0.0.1
      s = "\000" * (4 - (s.length % 4)) + s
      num = 0
      s.unpack('N*').each do |x|
        num <<= 32
        num |= x
      end
      num    
    end

    def Util.randomString(length, chars=nil)
      s = ""

      unless chars.nil?
        length.times { s << chars[Util.rand(chars.length)] }
      else
        length.times { s << Util.rand(256).chr }
      end
      s
    end

    def Util.urlencode(args)
      a = []
      args.each do |key, val|
        a << (CGI::escape(key) + "=" + CGI::escape(val))
      end
      a.join("&")
    end
    
    def Util.appendArgs(url, args)
      url if args.length == 0
      url << (url.include?("?") ? "&" : "?")
      url << Util.urlencode(args)
    end
    
    def Util.strxor(s1, s2)
      length = [s1.length, s2.length].min - 1
      a = (0..length).collect {|i| (s1[i]^s2[i]).chr}
      a.join("")
    end
    
    # Sign the given fields from the reply with the specified key.
    # Return [signed, sig]
  
    def Util.signReply(reply, key, signed_fields)
      token = []
      signed_fields.each do |sf|
        token << [sf+":"+reply["openid."+sf]+"\n"]
      end
      text = token.join("")
      signed = Util.toBase64(Util.hmacSha1(key, text))
      return [signed_fields.join(","), signed]
    end

    # This code is taken from this post[http://blade.nagaokaut.ac.jp/cgi-bin/scat.\rb/ruby/ruby-talk/19098]
    # by Eric Lee Green.
    # This implementation is much faster than x ** n % q
    def Util.powermod(x, n, q)
      counter=0
      n_p=n
      y_p=1
      z_p=x
      while n_p != 0
        if n_p[0]==1
          y_p=(y_p*z_p) % q
        end
        n_p = n_p >> 1
        z_p = (z_p * z_p) % q
        counter += 1
      end
      return y_p
    end

    # Generate a random number less than max.  Uses urandom if available.

    def Util.rand(max)
      unless Util::HAS_URANDOM
        return Kernel::rand(max)
      end

      start = 0
      stop = max
      step = 1
      r = ((stop-start)/step).to_i

      # figure out how many bytes we need
      rbytes = Util::numToStr(r)
      nbytes = rbytes.length
      nbytes -= 1 if rbytes[0].chr == "\000"
            
      bytes = "\000" + Util::_getBytes(nbytes)
      n = Util::strToNum(bytes)
      
      return start + (n % r) * step
    end

    # change the message below to do whatever you like for logging
    def Util.log(message)
      p 'OpenID Log: ' + message
    end


    def Util._getBytes(n)
      bytes = ""
      f = File.open("/dev/urandom")
      while n != 0
        _bytes = f.read(n)
        n -= _bytes.length
        bytes << _bytes
      end
      return bytes
    end

  end

end


