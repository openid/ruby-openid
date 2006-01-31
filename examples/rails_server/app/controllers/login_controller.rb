# Controller for handling the login, logout process for "users" of our
# little server.  Users have no password.  This is just an example.

class LoginController < ApplicationController

  layout 'server'

  def index
    # just show the login page
  end

  def submit
    user = @params[:username]

    # if we get a user, log them in by putting their username in
    # the session hash.
    unless user.nil?
      session[:username] = user unless user.nil?
      session[:approvals] = []
      flash[:notice] = "Your OpenID URL is <b>http://localhost:3000/user/#{user}</b><br/><br/>Proceed to step 2 below."
    else
      flash[:error] = "Sorry, couldn't log you in. Try again."
    end
    
    redirect_to :action => 'index'
  end

  def logout
    # delete the username from the session hash
    session[:username] = nil
    session[:approvals] = nil
    redirect_to :action => 'index'
  end

end
