require "base64"
require "cgi"
require "uri"
require "logger"

require "openid/extras"

srand(Time.now.to_f)

module OpenID

  # Code returned when either the of the
  # OpenID::OpenIDConsumer.begin_auth or OpenID::OpenIDConsumer.complete_auth
  # methods return successfully.
  SUCCESS = 'success'

  # Code OpenID::OpenIDConsumer.complete_auth
  # returns when the value it received indicated an invalid login.
  FAILURE = 'failure'

  # Code returned by OpenIDConsumer.complete_auth when the user
  # cancels the operation from the server.
  CANCEL = 'cancel'

  # Code returned by OpenID::OpenIDConsumer.complete_auth when the
  # OpenIDConsumer instance is in immediate mode and ther server sends back a
  # URL for the user to login with.
  SETUP_NEEDED = 'setup needed'

  # Code returned by OpenID::OpenIDConsumer.begin_auth when it is unable
  # to fetch the URL given by the user.
  HTTP_FAILURE = 'http failure'

  # Code returned by OpenID::OpenIDConsumer.begin_auth when the page fetched
  # from the OpenID URL doesn't contain the necessary link tags to function
  # as an identity page.
  PARSE_ERROR = 'parse error'

  class AssertionError < Exception
  end

  def assert(value, message=nil)
    if not value
      raise AssertionError, message or value
    end
  end

  module Util

    HAS_URANDOM = File.chardev? '/dev/urandom'

    def Util.to_base64(s)
      Base64.encode64(s).gsub("\n", "")
    end

    def Util.from_base64(s)
      Base64.decode64(s)
    end

    def Util.kvform(hash)
      form = ""
      hash.each do |k,v|
        form << "#{k}:#{v}\n"
      end
      form
    end

    def Util.urlencode(args)
      a = []
      args.each do |key, val|
        val = '' unless val
        a << (CGI::escape(key) + "=" + CGI::escape(val))
      end
      a.join("&")
    end

    def Util.parse_query(qs)
      query = {}
      CGI::parse(qs).each {|k,v| query[k] = v[0]}
      return query
    end

    def Util.append_args(url, args)
      url = url.dup
      return url if args.length == 0

      if args.respond_to?('each_pair')
        args = args.sort
      end

      url << (url.include?("?") ? "&" : "?")
      url << Util.urlencode(args)
    end

    @@logger = Logger.new(STDERR)
    @@logger.progname = "OpenID"

    def Util.logger=(logger)
      @@logger = logger
    end

    def Util.logger
      @@logger
    end

    # change the message below to do whatever you like for logging
    def Util.log(message)
      logger.info(message)
    end
  end

end
