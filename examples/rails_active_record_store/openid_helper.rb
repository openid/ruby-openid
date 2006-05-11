# load the openid library
begin
  require "rubygems"
  require_gem "ruby-openid", ">= 1.0"
rescue LoadError
  require "openid"
end

module OpenidHelper

  def get_auth_key
    setting = OpenidSetting.find :first, :conditions => "setting = 'auth_key'"
    if setting.nil?
      auth_key = OpenID::Util.random_string(20)
      setting = OpenidSetting.create :setting => 'auth_key', :value => auth_key
    end
    setting.value
  end

  def store_association(server_url, assoc)
    remove_association(server_url, assoc.handle)    
    OpenidAssociation.create(:server_url => server_url,
                             :handle => assoc.handle,
                             :secret => assoc.secret,
                             :issued => assoc.issued,
                             :lifetime => assoc.lifetime,
                             :assoc_type => assoc.assoc_type)
  end

  def get_association(server_url, handle=nil)
    
    unless handle.nil?
      assocs = OpenidAssociation.find(:all, :conditions => ["server_url = ? AND handle = ?", server_url, handle])
    else
      assocs = OpenidAssociation.find(:all, :conditions => ["server_url = ?", server_url])
    end

    return nil if assocs.nil?
    
    assocs.reverse!

    assocs.each do |assoc|
      a = assoc.from_record    
      if a.expired?
        assoc.destroy
      else
        return a
      end
    end

    return nil
  end

  def remove_association(server_url, handle)
    assoc = OpenidAssociation.find(:first, :conditions => ["server_url = ? AND handle = ?", server_url, handle])
    unless assoc.nil?
      assoc.destroy
      return true
      end
    return false
  end

  def store_nonce(nonce)
    use_nonce(nonce)
    OpenidNonce.create :nonce => nonce, :created => Time.now.to_i
  end

  def use_nonce(nonce)
    nonce = OpenidNonce.find(:first, :conditions => ["nonce = ?", nonce])
    return false if nonce.nil?
    
    age = Time.now.to_i - nonce.created    
    nonce.destroy

    return false if age > (6*60*60) # max nonce age of 6 hours
    return true
  end

  def dumb?
    return false
  end

  # not part of the api, but useful
  def gc
    now = Time.now.to_i

    # remove old nonces
    nonces = OpenidNonce.find(:all)
    nonces.each {|n| n.destroy if now - n.created > (6*60*60)} unless nonces.nil?

    # remove expired assocs
    assocs = OpenidAssociation.find(:all)
    assocs.each { |a| a.destroy if a.from_record.expired? } unless assocs.nil?
  end


end
