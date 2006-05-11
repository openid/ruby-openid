require 'pathname'

# load the openid library, first trying rubygems
begin
  require "rubygems"
  require_gem "ruby-openid", ">= 1.0"
rescue LoadError
  require "openid"
end

class ServerController < ApplicationController

  include ServerHelper
  include OpenID::Server
  layout nil
  
  def index
    begin
      request = server.decode_request(@params)
    rescue ProtocolError => e
      # invalid openid request, so just display a page with an error message
      render_text e.to_s
      return
    end
      
    # no openid.mode was given
    unless request
      render_text "This is an OpenID server endpoint."
      return
    end
    
    if request.kind_of?(CheckIDRequest)

      if self.is_authorized(request.identity_url, request.trust_root)
        response = request.answer(true)
        
        # add the sreg response if requested
        self.add_sreg(request, response)

      elsif request.immediate
        server_url = url_for :action => 'index'
        response = request.answer(false, server_url)
        
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
    
    # This is not technically correct, and should eventually be updated
    # to do real Accept header parsing and logic.  Though I expect it will work
    # 99% of the time.
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
      self.add_sreg(request, response)
      return self.render_response(response)
    end
  end

  protected

  def server
    if @server.nil?
      dir = Pathname.new(RAILS_ROOT).join('db').join('openid-store')
      store = OpenID::FilesystemStore.new(dir)
      @server = Server.new(store)
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
      <Type>http://openid.net/signon/1.0</Type>
      <Type>http://openid.net/sreg/1.0</Type>
      <URI>#{url_for(:controller => 'server')}</URI>
    </Service>
  </XRD>
</xrds:XRDS>
EOS

    response.headers['content-type'] = 'application/xrds+xml'
    render_text yadis
  end  

  def add_sreg(request, response)
    # Your code should examine request.query
    # for openid.sreg.required, openid.sreg.optional, and
    # openid.sreg.policy_url, and generate add fields to your response
    # accordingly. For this example, we'll just see if there are any
    # sreg args and add some sreg data to the response.  Take note,
    # that this does not actually respect the sreg query, it just sends
    # back some fake sreg data.  Your implemetation should be better! :)

    required = request.query['openid.sreg.required']
    optional = request.query['openid.sreg.optional']
    policy_url = request.query['openid.sreg.policy_url']

    if required or optional or policy_url
      # this should be taken out of the user's profile,
      # but since we don't have one lets just make up some data.
      # Also, the user should be able to approve the transfer
      # and modify each field if she likes.
      sreg_fields = {
        'email' => 'mayor@example.com',
        'nickname' => 'Mayor McCheese'
      }    
      response.add_fields('sreg', sreg_fields)
    end

  end

  def render_response(response)    
    web_response = server.encode_response(response)

    case web_response.code
    when HTTP_OK
      render_text web_response.body, :status => 200           

    when HTTP_REDIRECT
      redirect_to web_response.redirect_url

    else
      render_text web_response.body, :status => 400
    end   
  end


end
