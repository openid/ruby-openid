require 'pathname'

# load the openid library, first trying rubygems
#begin
#  require "rubygems"
#  require_gem "ruby-openid", ">= 1.0"
#rescue LoadError
require "openid"
require 'openid/extensions/sreg'
#end

class ServerController < ApplicationController

  include ServerHelper
  include OpenID::Server
  layout nil
  
  def index
    begin
      oidreq = server.decode_request(params)
    rescue ProtocolError => e
      # invalid openid request, so just display a page with an error message
      render_text e.to_s
      return
    end
      
    # no openid.mode was given
    unless oidreq
      render_text "This is an OpenID server endpoint."
      return
    end
    
    if oidreq.kind_of?(CheckIDRequest)

      if self.is_authorized(oidreq.identity, oidreq.trust_root)
        oidresp = oidreq.answer(true)
        
        # add the sreg response if requested
        self.add_sreg(oidreq, oidresp)

      elsif oidreq.immediate
        server_url = url_for :action => 'index'
        oidresp = oidreq.answer(false, server_url)
        
      else
        session[:last_oidreq] = oidreq
        @oidreq = oidreq
        flash[:notice] = "Do you trust this site with your identity?"
        render :template => 'server/decide', :layout => 'server'
        return
      end

    else
      oidresp = server.handle_request(oidreq)
    end
  
    self.render_response(oidresp)
  end

  def user_page
    # Yadis content-negotiation: we want to return the xrds if asked for.
    accept = request.env['HTTP_ACCEPT']
    
    # This is not technically correct, and should eventually be updated
    # to do real Accept header parsing and logic.  Though I expect it will work
    # 99% of the time.
    if accept and accept.include?('application/xrds+xml')
      render_xrds
      return
    end

    # content negotiation failed, so just render the user page    
    xrds_url = url_for(:controller=>'user',:action=>params[:username])+'/xrds'
    identity_page = <<EOS
<html><head>
<meta http-equiv="X-XRDS-Location" content="#{xrds_url}" />
<link rel="openid.server" href="#{url_for :action => 'index'}" />
</head><body><p>OpenID identity page for #{params[:username]}</p>
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
    oidreq = session[:last_oidreq]
    session[:last_oidreq] = nil

    if params[:yes].nil?
      redirect_to oidreq.cancel_url
      return
    else
      if session[:approvals]
        session[:approvals] << oidreq.trust_root
      else
        session[:approvals] = [oidreq.trust_root]
      end
      oidresp = oidreq.answer(true)
      self.add_sreg(oidreq, oidresp)
      return self.render_response(oidresp)
    end
  end

  protected

  def server
    if @server.nil?
      server_url = url_for :action => 'index', :only_path => false
      dir = Pathname.new(RAILS_ROOT).join('db').join('openid-store')
      store = OpenID::FilesystemStore.new(dir)
      @server = Server.new(store, server_url)
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
    xmlns="xri://$xrd*($v*2.0)">
  <XRD>
    <Service priority="0">
      <Type>http://specs.openid.net/auth/2.0/signon</Type>
      <Type>http://openid.net/signon/1.0</Type>
      <Type>http://openid.net/sreg/1.0</Type>
      <URI>#{url_for(:controller => 'server', :only_path => false)}</URI>
    </Service>
  </XRD>
</xrds:XRDS>
EOS

    response.headers['content-type'] = 'application/xrds+xml'
    render_text yadis
  end  

  def add_sreg(oidreq, oidresp)
    # check for Simple Registration arguments and respond
    sregreq = OpenID::SRegRequest.from_openid_request(oidreq)

    # In a real application, this data would be user-specific,
    # and the user should be asked for permission to release
    # it.
    sreg_data = {
      'nickname' => session[:username],
      'fullname' => 'Mayor McCheese',
      'email' => 'mayor@example.com'
    }
    
    if sregreq.were_fields_requested?
      sregresp = OpenID::SRegResponse.extract_response(sregreq, sreg_data)
      oidresp.add_extension(sregresp)
    end
  end

  def render_response(oidresp)
    if oidresp.needs_signing
      signed_response = server.signatory.sign(oidresp)
    end
    web_response = server.encode_response(oidresp)

    case web_response.code
    when HTTP_OK 
      render :text => web_response.body, :status => 200           

    when HTTP_REDIRECT
      redirect_to web_response.headers['location']

    else
      render :text => web_response.body, :status => 400
    end   
  end


end
