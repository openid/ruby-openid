#!/usr/bin/env ruby
require "cgi"
require "uri"
require "pathname"

require "webrick"
include WEBrick

# load the openid library, first trying rubygems
begin
  require "openid"
  require "openid/store/filestore"
  require "openid/extensions/sreg"
rescue LoadError
  require "rubygems"
  require_gem "ruby-openid"
end

################ start config ##########################
# use your desired store implementation here.
store_dir = Pathname.new(Dir.tmpdir).join("openid-store")
store = OpenID::FilesystemStore.new(store_dir)

$host = "localhost"
$port = 2000
################ end config ############################

if $port.nil?
  $base_url = "http://#{$host}/"
else
  $base_url = "http://#{$host}:#{$port}/"
end

# NOTE: Please note that a Hash is not a valid session storage type, it is just
# used here to get something that works.  In a production environment this
# should be an object representing the CURRENT USER's session, NOT a global
# hash.  Every user visiting this running consumer.rb will write into this
# same hash.
$session = {}

$trust_root = $base_url
$consumer = OpenID::Consumer.new($session, store)

server = HTTPServer.new(:Port=>$port)
class SimpleServlet < HTTPServlet::AbstractServlet

  def do_GET(req, res)
    @req = req
    @res = res

    begin
      case req.path
      when "", "/", "/start"
        render
      when "/begin"
        do_begin
      when "/complete"
        do_complete
      when '/policy'
        do_policy
      else
        redirect(build_url)
      end
    ensure
      @req = nil
      @res = nil
    end
  end

  def do_POST(req, res)
    do_GET(req, res)
  end

  def policy_url
    build_url('policy')
  end

  def return_to
    build_url('complete')
  end

  def do_begin
    # First make sure the user entered something
    openid_identifier = @req.query.fetch("openid_identifier", "")

    if openid_identifier.empty?
      render("Enter an OpenID identifier to verify",
             css_class="error", form_contents=openid_identifier)
      return HTTPStatus::Success
    end

    # Then ask the openid library to begin the authorization
    begin
      checkid_request = $consumer.begin(openid_identifier)
    rescue OpenID::Yadis::DiscoveryFailure => why
      # If the URL was unusable (either because of network conditions,
      # a server error, or that the response returned was not an
      # OpenID identity page), the library will raise
      # OpenID::Yadis::DiscoveryFailure Let the user know that the URL
      # is unusable.
      render("Error performing discovery: #{why.message}",
             "error", openid_identifier)
      return HTTPStatus::Success
    end

    # check to see if we want to make an SREG request. Generally this will
    # not take the form of a checkbox, but will be part of your site policy.
    # For example, you may perform an sreg request if the user appears
    # to be new to the site.  The checkbox is here for convenience of
    # testing.
    if @req.query.fetch('sreg', false)
      required = ['email', 'nickname']
      optional = ['fullname', 'dob', 'gender', 'postcode', 'country']
      sreg_req = OpenID::SRegRequest.new(required, optional, policy_url)
      checkid_request.add_extension(sreg_req)

      # Only necessary so that we can maintain the checkbox state when
      # the user returns.
      checkid_request.return_to_args['did_sreg'] = 'true'
    end

    # The URL was a valid identity URL. Now we just need to send a redirect
    # to the server using the redirect_url the library created for us.
    # build the redirect
    #
    # XXX: Use form redirection when appropriate
    redirect_url = checkid_request.redirect_url($trust_root, return_to)

    # send redirect to the server
    redirect(redirect_url)
  end

  # handle the redirect from the OpenID server
  def do_complete
    # Ask the library to check the response that the server sent
    # us.  Status is a code indicating the response type. info is
    # either nil or a string containing more information about
    # the return type.
    response = $consumer.complete(@req.query, return_to)

    css_class = "error"

    case response.status
    when OpenID::Consumer::FAILURE
      # In the case of failure, if the identifier is non-nil, it is
      # the URL that we were verifying. We include it in the error
      # message to help the user figure out what happened.
      identifier = response.identity_url ? " of #{response.identity_url}" : ""

      # add on the failure message for a little debug info
      message = "Verification#{identifier} failed: #{response.message}"

    when OpenID::Consumer::SUCCESS
      # Success means that the OpenID authentication completed without
      # error.
      css_class = "alert"

      message = ("You have successfully verified #{response.identity_url} "\
                 "as your identity.")

      did_sreg = @req.query.fetch('did_sreg', false)
      if did_sreg
        message << " Simple registration data were requested"
        sreg_resp = OpenID::SRegResponse.from_success_response(response)
        if sreg_resp.empty?
          message << ", but no data were sent."
        else
          message << ". The following data were sent:"
          sreg_resp.data.each_pair do |k, v|
            message << "<br/><b>#{k}</b>: #{v}"
          end
        end
      end

    when OpenID::Consumer::CANCEL
      message = "Verification cancelled."

    when OpenID::Consumer::SETUP_NEEDED
      message = ("Setup needed should not be sent, since we didn't make "\
                 "an immediate request")
    else
      message = "Unknown response status: #{response.status}"

    end
    render(message, css_class, response.identity_url, did_sreg)
  end

  def do_policy
    @res.body = <<END
<html>
<head></head>
<body>
<h3>Ruby Consumer Simple Registration Policy</h3>
<p>This consumer makes a simple registration request for the following fields:<br/><br/>
<b>Required:</b> email, nickname<br/>
<b>Optional:</b> fullname, dob, gender, postcode, country<br/><br/>
Nothing is actually done with the data provided, it simply exists to illustrate the simple registration protocol.
</p>
</body>
</html>

END
  end

  # build a URL relative to the server base URL, with the given query
  # parameters added.
  def build_url(action='', query=nil)
    url = URI.parse($base_url).merge(action).to_s
    url = OpenID::Util.append_args(url, query) unless query.nil?
    return url
  end

  def redirect(url)
    @res.set_redirect(HTTPStatus::TemporaryRedirect, url)
  end

  def render(message=nil, css_class="alert", form_contents="", checked=false)
    @res.body = page_header
    unless message.nil?
      @res.body << "<div class=\"#{css_class}\">#{message}</div>"
    end
    checked = checked ? " checked='checked'" : ''
    @res.body << page_footer(form_contents, checked)
  end

  def page_header(title="Ruby OpenID WEBrick example")
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
      This example consumer uses the <a href="http://openidenabled.com/openid/libraries/ruby">Ruby OpenID</a> library
      on a WEBrick platform.  The example just verifies that the URL that
      you enter is your identity URL.
    </p>
END_OF_STRING
  end


  def page_footer(form_contents="", checked="")
    form_contents = "" if form_contents == "/"
    footer = <<END_OF_STRING
    <div id="verify-form">
      <form method="get" action="#{self.build_url("/begin")}">
        Identity&nbsp;URL:
      <input type="text" name="openid_identifier" value="#{form_contents}" />
        <input type="submit" value="Verify" />
        <input type="checkbox" id="sregbox" name="sreg" #{checked} />
        <label for="sregbox">with simple registration</label>
        <a href="http://www.openidenabled.com/openid/simple-registration-extension" target="_blank">?</a>
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
