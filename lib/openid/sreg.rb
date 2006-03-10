require "openid/extensions"

module OpenID

  class SREG < Extension
    @prefix = 'sreg'
    @schema = ['nickname', 'email', 'fullname', 'dob', 'gender',
               'postcode', 'country', 'language', 'timezone']
  end

end
