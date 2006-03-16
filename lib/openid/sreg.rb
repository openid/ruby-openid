require "openid/extensions"

module OpenID

  class SREG < Extension

    @url = 'http://www.openidenabled.com/openid/simple-registration-extension/'
    @prefix = 'sreg'
    @schema = ['nickname', 'email', 'fullname', 'dob', 'gender',
               'postcode', 'country', 'language', 'timezone']
 
 end

end
