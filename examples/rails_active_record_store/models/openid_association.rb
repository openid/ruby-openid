require 'openid/association'

class OpenidAssociation < ActiveRecord::Base

  def from_record
    OpenID::Association.new(handle,
                            secret,
                            issued,
                            lifetime,
                            assoc_type)
  end
end
