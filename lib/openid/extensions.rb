require "openid/util"

module OpenID
  
  class Extension

    def Extension.check(secret, query)
      e = create(secret, query)
      return nil if e.nil?
      return e.check_sig
    end

    def Extension.create(secret, query)
      return nil unless query[@prefix+'.sig']
      return nil unless query['openid.sig']
      new(secret, query, @prefix, @schema)
    end

    def Extension.uses_extension(query)
      return query.has_key?(@prefix+'.sig')
    end

    def Extension.extract(query)
      args = {}
      @schema.each do |s|
        key = @prefix + '.' + 's'
        args[key] = query[key] if query.has_key?(key)
      end
      args
    end

    def Extension.prefix
      @prefix
    end

    def Extension.schema
      @schema
    end

    def Extension.protocol_url
      @url
    end

    def check_sig
      gen_sig == @extension_sig
    end

    def gen_sig
      OpenID::Util.to_base64(OpenID::Util.hmac_sha1(@secret, ext_content))
    end

    def ext_content
      text = "openid.sig:"+@openid_sig+"\n"
      @query.keys.sort.each do |key|
        text << key+':'+@query[key]+"\n"
      end
      return text
    end

    private

    def initialize(secret, query, prefix, schema, url)
      @prefix = prefix
      @schema = schema
      @url = url

      @secret = secret
      @openid_sig = query['openid.sig']
      @extension_sig = query[@prefix+'.sig']

      q = {}
      @schema.each do |s|
        key = @prefix+'.'+s
        val = query[key]
        q[key] = val unless val.nil?
      end

      @query = q
    end

  end

  class SREG < Extension
    @prefix = 'sreg'
    @schema = ['nickname', 'email', 'fullname', 'dob', 'gender',
               'postcode', 'country', 'language', 'timezone']

  end

end
