begin
  require "rubygems"
  require_gem "ruby-openid", ">= 1.0"
rescue LoadError
  require "openid"
end

class OpenidAssociation < ActiveRecord::Base

  def from_record
    OpenID::Association.new(handle,
                            secret,
                            issued,
                            lifetime,
                            assoc_type)
  end
end
