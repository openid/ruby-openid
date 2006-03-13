require 'tmpdir'
require 'pathname'

require 'openid/filestore'
require 'openid/server'
require 'openid/server'

class ServerController < ApplicationController

  include ServerHelper
  layout nil
  
  def index
    status, info = server.get_openid_response(@request.method.to_s, @params,
                                              is_authorized)

    return handle_openid_response(status, info)
  end

  def user_page
    # Yadis content-negotiation: we want to return the xrds if asked for.
    accept = request.env['HTTP_ACCEPT']
    if accept and accept.include?('application/xrds+xml')
      render_xrds
      return
    end

    # content negotiation failed, so just render the user page    
    xrds_url = url_for(:controller=>'user',:action=>@params[:username])+'/xrds'
    identity_page = <<EOS
<html><head>
<meta http-equiv="X-XRDS-Location" content="#{xrds_url}" />
</head><body><p>OpenID identity page for #{@params[:username]}</p>
</body></html>
EOS
    # Also add the Yadis location header, so that they don't have
    # to parse the html unless absolutely necessary.
    response.headers['X-XRDS-Location'] = xrds_url
    render_text identity_page
  end

  def xrds
    render_xrds
  end

  def decision
    auth_info = OpenID::AuthorizationInfo.deserialize(@params[:auth_info])

    if @params[:yes].nil?
      redirect_to auth_info.cancel_url
      return
    else
      session[:approvals] << auth_info.trust_root
      status, info = auth_info.retry(server, is_authorized)
      return handle_openid_response(status, info)
    end
  end

  private

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

  # Please note that for simplicity, this example uses the filestore and
  # places it's files in /tmp.  This is NOT a good idea for production servers!
  # Make sure to put the filstore directory in a place unavailable to other
  # system users.
  def server
    if @server.nil?
      dir = Pathname.new(Dir.tmpdir).join('openid-server')
      store = OpenID::FilesystemOpenIDStore.new(dir)
      server_url = url_for :controller => 'server'
      @server = OpenID::OpenIDServer.new(server_url, store)
    end
    return @server
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

  def render_xrds
    yadis = <<EOS
<?xml version="1.0" encoding="UTF-8"?>
<xrds:XRDS
    xmlns:xrds="xri://$xrds"
    xmlns:openid="http://openid.net/xmlns/1.0"
    xmlns="xri://$xrd*($v*2.0)">
  <XRD>
    <Service priority="1">
      <Type>http://openid.net/signon/1.1</Type>
      <URI>#{url_for(:controller => 'server')}</URI>
    </Service>
  </XRD>
</xrds:XRDS>
EOS

    response.headers['content-type'] = 'application/xrds+xml'
    render_text yadis
  end


end
