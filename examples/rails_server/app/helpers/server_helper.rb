require 'tmpdir'
require 'pathname'

require 'openid/filestore'
require 'openid/server'

# Please note that for simplicity, this example uses the filestore and
# places it's files in /tmp.  This is NOT a good idea for production servers!
# Make sure to put the filstore directory in a place unavailable to other
# system users.

module ServerHelper

  def handle_openid_response(status, info)
    case status
    when OpenID::REDIRECT
      redirect_to info
      return 

    when OpenID::DO_AUTH

      # make sure a user is logged in, and it is the right user
      if session[:username].nil? or (url_for_user != info.identity_url)
        redirect_to :controller => 'login', :action => 'logout'
        return
      end

      @auth_info = info
      flash[:notice] = "Do you trust this site with your identity?"
      render :template => 'server/decide', :layout => 'server'
      return

    when OpenID::REMOTE_OK
      render_text info, :status => 200
      return

    when OpenID::REMOTE_ERROR
      render_text info, :status => 400
      return

    when OpenID::LOCAL_ERROR
      render_text info
      return

    when OpenID::DO_ABOUT
      render_text "This is an OpenID server endpoint."
      return
      
    end
  end

  def server
    if @server.nil?
      dir = Pathname.new(Dir.tmpdir).join('openid-server')
      store = OpenID::FilesystemOpenIDStore.new(dir)
      server_url = url_for :controller => 'server'
      @server = OpenID::OpenIDServer.new(server_url, store)
    end
    return @server
  end

  def url_for_user
    url_for :controller => 'user', :action => session[:username]
  end

  def approved(trust_root)
    return false if session[:approvals].nil?
    return session[:approvals].member?(trust_root)
  end

  def is_authorized
    Proc.new do |identity_url, trust_root|
      (not session[:username].nil?) and (identity_url == url_for_user) and \
      approved(trust_root)
    end
  end



end

