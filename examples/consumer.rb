#!/usr/bin/env ruby
require "cgi"
require "uri"
require "tmpdir"
require "pathname"

require "webrick"
include WEBrick

require "openid/consumer"
require "openid/filestore"

################ endconfig ##########################
# use your desired store implementation here
store_dir = Pathname.new(Dir.tmpdir).join("rubyopenid")
store = OpenID::FilesystemOpenIDStore.new(store_dir)

$host = "localhost"
$port = 2000
################ end config ##########################

$consumer = OpenID::OpenIDConsumer.new(store)

if $port.nil?
  $base_url = "http://#{$host}/"
else
  $base_url = "http://#{$host}:#{$port}/"
end


server = HTTPServer.new(:Port=>$port)

class SimpleServlet < HTTPServlet::AbstractServlet

  def do_GET(req, res)
    @req = req
    @res = res
    begin
      case req.path
      when "", "/", "/start"
        self.render
      when "/begin"
        self.doBegin
      when "/complete"
        self.doComplete
      else
        self.redirect(self.buildURL("/"))
      end
    ensure
      @req = nil
      @res = nil
    end
  end 

  def doBegin
    # First make sure the user entered something
    openid_url = @req.query.fetch("openid_url", "")
    if openid_url.empty?
      self.render("Enter an identity URL to verify",
                  css_class="error", form_contents=openid_url)
      return HTTPStatus::Success
    end    
    
    # Then ask the openid library to begin the authorization
    status, info = $consumer.beginAuth(openid_url)
    
    # If the URL was unusable (either because of network conditions,
    # a server error, or that the response returned was not an OpenID
    # identity page), the library will return HTTP_FAILURE or PARSE_ERROR.
    # Let the user know that the URL is unusable.
    case status
    when OpenID::HTTP_FAILURE
      self.render("Failed to retrieve <q>#{openid_url}</q>",
                  css_class="error", form_contents=openid_url)
      return HTTPStatus::Success

    when OpenID::PARSE_ERROR
      self.render("Failed to retrieve <q>#{openid_url}</q>",
                  css_class="error", form_contents=openid_url)
      return HTTPStatus::Success

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
      return_to = self.buildURL("/complete", {"token"=>info.token})

      # Now ask the library for the URL to redirect the user to
      # his OpenID server. The auth request is what the library
      # returned before. We just constructed the return_to. The
      # return_to URL must be under the specified trust_root. We
      # just use the base_url for this server as a trust root.
      redirect_url = $consumer.constructRedirect(info,
                                                 return_to,
                                                 trust_root=$base_url)
      
      # Send the redirect response
      self.redirect(redirect_url)
    else
      # Should never get here
      raise "Not Reached"
    end    
  end

  # handle the redirect from the OpenID server
  def doComplete
    # get the token from the environment (in this case, the URL)
    token = @req.query.fetch("token", "")

    # Ask the library to check the response that the server sent
    # us.  Status is a code indicating the response type. info is
    # either nil or a string containing more information about
    # the return type.
    status, info = $consumer.completeAuth(token, @req.query)

    css_class = "error"
    openid_url = nil
    
    if status == OpenID::FAILURE and info
      # In the case of failure, if info is non-nil, it is the
      # URL that we were verifying. We include it in the error
      # message to help the user figure out what happened.
      openid_url = info
      message = "Verification of #{openid_url} failed"

    elsif status == OpenID::SUCCESS
      # Success means that the transaction completed without
      # error. If info is nil, it means that the user cancelled
      # the verification.
      css_class = "alert"
      if info
        openid_url = info
        message = "You have successfully verified #{openid_url} as your identity."
      else
        # cancelled
        message = "Verification cancelled."
      end
    else
      # Either we don't understand the code or there is no
      # openid_url included with the error. Give a generic
      # failure message. The library should supply debug
      # information in a log.
      message = "Verification failed."      
    end
    self.render(message, css_class, openid_url)
  end

  # build a URL relative to the server base URL, with the given query
  # parameters added.
  def buildURL(action, query=nil)
    url = @req.request_uri.merge(action).to_s
    url = OpenID::Util.appendArgs(url, query) unless query.nil?
    url
  end
   
  def redirect(url)
    @res.set_redirect(HTTPStatus::MovedPermanently, url)
  end

  def render(message=nil, css_class="alert", form_contents="")
    @res.body = self.pageHeader
    unless message.nil?
      @res.body << "<div class=\"#{css_class}\">#{message}</div>"
    end
    @res.body << self.pageFooter(form_contents)    
  end

  def pageHeader(title="Ruby OpenID WEBrick example")
    header = <<END_OF_STRING
<html>
  <head><title>#{title}</title></head>
  <style type="text/css">
      * {
        font-family: verdana,sans-serif;
      }
      body {
        width: 50em;
        margin: 1em;
      }
      div {
        padding: .5em;
      }
      table {
        margin: none;
        padding: none;
      }
      .alert {
        border: 1px solid #e7dc2b;
        background: #fff888;
      }
      .error {
        border: 1px solid #ff0000;
        background: #ffaaaa;
      }
      #verify-form {
        border: 1px solid #777777;
        background: #dddddd;
        margin-top: 1em;
        padding-bottom: 0em;
      }
  </style>
  <body>
    <h1>#{title}</h1>
    <p>
      This example consumer uses the Ruby-OpenID-Consumer library
      on a WEBrick platform.  The example just verifies that the URL that
      you enter is your identity URL.
    </p>
END_OF_STRING
  end


  def pageFooter(form_contents="")
    form_contents = "" if form_contents == "/"    
    footer = <<END_OF_STRING
    <div id="verify-form">
      <form method="get" action=#{self.buildURL("/begin")}>
        Identity&nbsp;URL:
      <input type="text" name="openid_url" value="#{form_contents}" />
        <input type="submit" value="Verify" />
      </form>
    </div>
  </body>
</html>
END_OF_STRING
  end


end

# Bootstrap the example
server.mount("/", SimpleServlet)
trap("INT") {server.shutdown}
print "\nVisit http://#{$host}:#{$port}/ in your browser.\n\n"
server.start

