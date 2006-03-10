require "tmpdir"
require "pathname"

require "openid/consumer"
require "openid/filestore"

class OpenidController < ApplicationController
  layout "openid-layout"

  # Action for handling user entered OpenID URL
  def begin_auth
    @msg_class = "error"
    
    # make sure the user actually entered something
    openid_url = @params["openid_url"]
    if openid_url.nil?
      @msg = "Enter your OpenID URL below"
      return
    end
    
    consumer = get_consumer
    
    # ask the openid library to begin the authorization
    status, info = consumer.begin_auth(openid_url)
    
    case status      
    when OpenID::SUCCESS
      # The URL was a valid identity URL. Now we construct a URL
      # that will get us to process the server response. We will
      # need the token from the auth request when processing the
      # response, so we have to save it somewhere. The obvious
      # options are including it in the URL, storing it in a
      # cookie, and storing it in a session object if one is
      # available. For this example, we have no session and we
      # do not want to deal with cookies, so just add it as a
      # query parameter to the URL.      
      return_to = url_for(:action=>"complete_auth", :token=>info.token)
      trust_root = url_for(:controller => "openid")
      redirect_url = consumer.construct_redirect(info, return_to,
                                                  trust_root=trust_root)

      # send redirect via user's browser to their openid server
      redirect_to(redirect_url)

    when OpenID::HTTP_FAILURE
      # If the URL was unusable (either because of network conditions,
      # a server error, or that the response returned was not an OpenID
      # identity page), the library will return HTTP_FAILURE or PARSE_ERROR.
      # Let the user know that the URL is unusable.
      @msg = "Unable to fetch #{openid_url}"

    when OpenID::PARSE_ERROR
      @msg = "Could not find openid.server on page #{openid_url}"

    else
      @msg = "Error.  Unknown status: #{status}"
    end
  end

  def complete_auth
    # get the token from the environment, in this case the URL
    token = @params["token"]
    
    status, info = get_consumer.complete_auth(token, @params)

    @msg_class = "error"

    if status == OpenID::FAILURE and info
      # In the case of failure, if info is non-nil, it is the
      # URL that we were verifying. We include it in the error
      # message to help the user figure out what happened.
      openid_url = info
      @msg = "Verification of #{openid_url} failed"

    elsif status == OpenID::SUCCESS
      # Success means that the transaction completed without
      # error. If info is nil, it means that the user cancelled
      # the verification.
      @msg_class = "alert"
      if info
        openid_url = info
        @msg = "You have successfully verified #{openid_url} as your identity."
      else
        # cancelled
        @msg = "Verification cancelled."
      end
    else
      # Either we don't understand the code or there is no
      # openid_url included with the error. Give a generic
      # failure message. The library should supply debug
      # information in a log.
      message = "Verification failed."      
    end

  end

  private
  
  def get_consumer
    store_dir = Pathname.new(Dir.tmpdir).join("rubyopenid")
    store = OpenID::FilesystemOpenIDStore.new(store_dir)
    OpenID::OpenIDConsumer.new(store, @session)    
  end

end

