require "openid/extensions"

module OpenID

  class SREG < Extension

    attr_reader :prefix, :schema

    @url = 'http://www.openidenabled.com/openid/simple-registration-extension/'
    @prefix = 'sreg'
    @schema = ['nickname', 'email', 'fullname', 'dob', 'gender',
               'postcode', 'country', 'language', 'timezone']
 
 end

end
