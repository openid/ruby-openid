# make sure to look at app/helpers/server_helper.rb as well

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
    identity_page = <<EOS
<html><head>
<link rel="openid.server" href="#{url_for :controller => 'server'}" />
</head><body><p>OpenID identity page for #{@params[:username]}</p>
</body></html>
EOS
    render_text identity_page
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


end
