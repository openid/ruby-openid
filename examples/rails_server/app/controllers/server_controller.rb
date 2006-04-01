require 'tmpdir'
require 'pathname'

require 'openid/filestore'
require 'openid/server2'

class ServerController < ApplicationController

  include ServerHelper
  layout nil
  
  def index
    request = server.decode_request(@params)

    # no openid.mode was given
    unless request
      render_text "This is an OpenID server endpoint."
      return
    end
    
    if request.class == OpenID::Server::CheckIDRequest

      if self.is_authorized(request.identity_url, request.trust_root)
        response = request.answer(true)
        self.add_sreg(response)

      elsif request.immediate
        # immediate mode and not authorized, send 'em to setup url
        retry_query = query.dup
        retry_query['openid.mode'] = 'checkid_setup'
        setup_url = url_for :action => 'index'
        setup_url = OpenID::Util.append_args(setup_url, retry_query)
        response = request.answer(false, setup_url)
        
      else
        @session[:last_request] = request
        @request = request
        flash[:notice] = "Do you trust this site with your identity?"
        render :template => 'server/decide', :layout => 'server'
        return
      end

    else
      response = server.handle_request(request)
    end
  
    self.render_response(response)
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
<link rel="openid.server" href="#{url_for :action => 'index'}" />
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
    request = @session[:last_request]
    @session[:last_request] = nil

    if @params[:yes].nil?
      redirect_to request.cancel_url
      return
    else
      session[:approvals] << request.trust_root
      response = request.answer(true)
      self.add_sreg(response)
      return self.render_response(response)
    end
  end

  protected

  # Please note that for simplicity, this example uses the filestore and
  # places it's files in /tmp.  This is NOT a good idea for production servers!
  # Make sure to put the filstore directory in a place unavailable to other
  # system users.
  def server
    if @server.nil?
      dir = Pathname.new(Dir.tmpdir).join('openid-server')
      store = OpenID::FilesystemOpenIDStore.new(dir)
      @server = OpenID::Server::OpenIDServer.new(store)
    end
    return @server
  end

  def approved(trust_root)
    return false if session[:approvals].nil?
    return session[:approvals].member?(trust_root)
  end

  def is_authorized(identity_url, trust_root)
    return (session[:username] and (identity_url == url_for_user) and self.approved(trust_root))
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

  def add_sreg(response)
    # this should be taken out of the user's profile,
    # but since we don't have one lets just make up some data.
    # Also, the user should be able to approve the transfer
    # and modify each field if she likes.
    sreg = {
      'openid.sreg.email' => 'foo@example.com',
      'openid.sreg.nickname' => 'Mr. Foo'
    }
    
    response.fields.update(sreg)
    response.signed += ['sreg.nickname', 'sreg.email']    
  end

  def render_response(response)    
    response = server.encode_response(response)

    case response.code
    when OpenID::Server::HTTP_OK
      render_text response.body, :status => 200           
    when OpenID::Server::HTTP_REDIRECT
      redirect_to response.redirect_url
    else
      render_text response.body, :status => 400
    end   
  end


end
