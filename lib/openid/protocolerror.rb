require 'openid/util'

module OpenID

  # An error in the OpenID protocol
  #
  # Note: there is also a OpenID::Server::ProtocolError which is
  #   a distinct class used exclusively in Server contexts
  #
  class ProtocolError < OpenIDError
  end
end
