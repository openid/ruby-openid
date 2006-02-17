require "openid/filestore"
require "openid/consumer"

store = OpenID::FilesystemOpenIDStore.new("/tmp/railsgen")
$consumer = OpenID::OpenIDConsumer.new(store)

class <%= class_name %>Controller < ApplicationController
  layout  'scaffold'

  def login
    openid_url = @params[:identity_url]

    if @request.post?
      status, info = $consumer.begin_auth(openid_url)
      case status
      when OpenID::SUCCESS
        return_to = url_for(:action=>:complete_auth, :token=>info.token)
        trust_root = url_for(:controller=>"")
        redirect_url = $consumer.construct_redirect(info, return_to, trust_root)

        redirect_to(redirect_url)

      when OpenID::PARSE_ERROR
        flash[:notice] = "Could not find OpenID server for page #{openid_url}"
        
      when OpenID::HTTP_FAILURE
        flash[:notice] = "Could not fetch page #{openid_url}"

      end      
    end    
  end

  def complete_auth
    token = @params[:token]
    
    status, info = $consumer.complete_auth(token, @params)
    
    if status == OpenID::SUCCESS
      openid_url = info

      @user = User.get(openid_url)
      
      # create user object if one does not exist
      if @user.nil?
        @user = User.new(:openid_url => openid_url)
        @user.save
      end
      @session[:user] = @user 

      @session[:user] = openid_url
      flash[:notice] = "Logged in as #{openid_url}"
       
      redirect_to :action => "welcome"
      return

    elsif status == OpenID::FAILURE and info
      flash[:notice] = "Verification of #{info} failed."

    else
      flash[:notice] = "Verification cancelled"
    end
  
    redirect_to :action => "login"
  end
  
  def logout
    @session[:user] = nil
  end
    
  def welcome
  end
  
end
