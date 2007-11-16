require "openid/consumer"
require 'openid/server'

# See OpenID::Consumer or OpenID::Server modules, as well as the store classes
module OpenID
  VERSION = "2.0.0-dev"

  # Exceptions that are raised by the library are subclasses of this
  # exception type, so if you want to catch all exceptions raised by
  # the library, you can catch OpenIDError
  class OpenIDError < StandardError
  end
end
