require 'openid/util'

module OpenID

    # Consumer's view of an association with a server
  class Association

    @@assoc_keys = [
      'version',
      'server_url',
      'handle',
      'secret',
      'issued',
      'lifetime'
    ]

    attr_reader :server_url, :handle, :secret, :issued, :lifetime

    def Association.from_expires_in(expires_in, server_url,
                                          handle, secret)
      issued = Time.now.to_i
      lifetime = expires_in
      new(server_url, handle, secret, issued, lifetime) 
    end

    def Association.serialize(assoc)
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

    def Association.deserialize(assoc_s)
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
      Association.new(server_url, handle, secret, issued, lifetime)
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

end
