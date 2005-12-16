# interface.rb documents the main interface with the OpenID consumer
# libary.  The only part of the library which has to be used and isn't
# documented in full here is the store required to create an
# OpenIDConsumer instance.  More on the abstract store type and
# concrete implementations of it that are provided in the documentation
# for the initialize method of the OpenIDConsumer class.
#
# OVERVIEW
# ========
#
# The OpenID identity verification process most commonly uses the
# following steps, as visible to the user of this library:
#
#   1. The user enters their OpenID into a field on the consumer's
#      site, and hits a login button.
#
#   2. The consumer site checks that the entered URL describes an
#      OpenID page by fetching it and looking for appropriate link
#      tags in the head section.
#
#   3. The consumer site sends the browser a redirect to the
#      identity server.  This is the authentication request as
#      described in the OpenID specification.
#
#   4. The identity server's site sends the browser a redirect
#      back to the consumer site.  This redirect contains the
#      server's response to the authentication request.
#
# The most important part of the flow to note is the consumer's site
# must handle two separate HTTP requests in order to perform the
# full identity check.
#
# LIBRARY DESIGN
# ==============
#
# This consumer library is designed with that flow in mind.  The
# goal is to make it as easy as possible to perform the above steps
# securely.
#
# At a high level, there are two important parts in the consumer
# library.  The first important part is this file, which contains
# the interface to actually use this library.  The second is the
# openid/stores.rb file, which describes the interface to
# use if you need to create a custom method for storing the state
# this library needs to maintain between requests.
#
# In general, the second part is less important for users of the
# library to know about, as a file-based store implementation is provided.
# See openid/consumer/filestore.rb
#
# This file contains a class, OpenIDConsumer, with methods
# corresponding to the actions necessary in each of steps 2, 3, and
# 4 described in the overview.  Use of this library should be as easy
# as creating an OpenIDConsumer instance and calling the methods
# appropriate for the action the site wants to take.
#
# STORES AND DUMB MODE
# ====================
#
# OpenID is a protocol that works best when the consumer site is
# able to store some state.  This is the normal mode of operation
# for the protocol, and is sometimes referred to as smart mode.
# There is also a fallback mode, known as dumb mode, which is
# available when the consumer site is not able to store state.  This
# mode should be avoided when possible, as it leaves the
# implementation more vulnerable to replay attacks.
#
# The mode the library works in for normal operation is determined
# by the store that it is given.  The store is an abstraction that
# handles the data that the consumer needs to manage between http
# requests in order to operate efficiently and securely.
#
# Several store implementation are provided, and the interface is
# fully documented so that custom stores can be used as well.  See
# the documentation for the C{L{OpenIDConsumer}} class for more
# information on the interface for stores.  The concrete
# implementations that are provided allow the consumer site to store
# the necessary data in several different ways: in the filesystem,
# # XXX other stores to be implemeted in ruby
#
# There is an additional concrete store provided that puts the
# system in dumb mode.  This is not recommended, as it removes the
# library's ability to stop replay attacks reliably.  It still uses
# time-based checking to make replay attacks only possible within a
# small window, but they remain possible within that window.  This
# store should only be used if the consumer site has no way to store
# data between requests at all.
#
# IMMEDIATE MODE
# ==============
#
# In the flow described above, the user may need to confirm to the
# identity server that it's ok to authorize his or her identity.
# The server may draw pages asking for information from the user
# before it redirects the browser back to the consumer's site.  This
# is generally transparent to the consumer site, so it is typically
# ignored as an implementation detail.
#
# There can be times, however, where the consumer site wants to get
# a response immediately.  When this is the case, the consumer can
# put the library in immediate mode.  In immediate mode, there is an
# extra response possible from the server, which is essentially the
# server reporting that it doesn't have enough information to answer
# the question yet.  In addition to saying that, the identity server
# provides a URL to which the user can be sent to provide the needed
# information and let the server finish handling the original
# request.
#
# USING THIS LIBRARY
# ==================
#
# Integrating this library into an application is usually a
# relatively straightforward process.  The process should basically
# follow this plan:
#
# Add an OpenID login field somewhere on your site.  When an OpenID
# is entered in that field and the form is submitted, it should make
# a request to the your site which includes that OpenID URL.
#
# When your site receives that request, it should create an
# OpenIDConsumer instance, and call OpenIDConsumer.beginAuth on it.  If
# beginAuth completes successfully, it will return an OpenIDAuthRequest.
# Otherwise it will provide some useful information for giving the user
# an error message.
#
# Now that you have the OpenIDAuthRequest object, you need to
# preserve the value in its OpenIDAuthRequest.token
# field for lookup on the user's next request from your site.  There
# are several approaches for doing this which will work.  If your
# environment has any kind of session-tracking system, storing the
# token in the session is a good approach.  If it doesn't you can
# store the token in either a cookie or in the return_to url
# provided in the next step.
#
# The next step is to call the OpenIDConsumer.constructRedirect method
# on the C{L{OpenIDConsumer}} object.  Pass it the
# OpenIDAuthRequest object returned by the previous call to
# OpenIDConsumer.beginAuth along with the return_to
# and trust_root URLs.  The return_to URL is the URL that the OpenID
# server will send the user back to after attempting to verify his
# or her identity.  The trust_root is the URL (or URL pattern) that
# identifies your web site to the user when he or she is authorizing
# it.
#
# Next, send the user a redirect to the URL generated by
# OpenIDConsumer.constructRedirect.
#
# That's the first half of the process.  The second half of the
# process is done after the user's ID server sends the user a
# redirect back to your site to complete their login.
#
# When that happens, the user will contact your site at the URL
# given as the return_to URL to the OpenIDConsumer.constructRedirect call
# made above.  The request will have several query parameters added
# to the URL by the identity server as the information necessary to
# finish the request.
#
# When handling this request, the first thing to do is check the
# openid.return_to parameter.  If it doesn't match the URL that
# the request was actually sent to (the URL the request was actually
# sent to will contain the openid parameters in addition to any in
# the return_to URL, but they should be identical other than that),
# that is clearly suspicious, and the request shouldn't be allowed
# to proceed.
#
# Otherwise, the next step is to extract the token value set in the
# first half of the OpenID login.  Create a OpenIDConsumer
# object, and call its completeAuth method with that token and a dictionary
# of all the query arguments.  This call will return a status code and some
# additional information describing the the server's response.  See the
# documuntation for OpenIDConsumer.completeAuth for a full
# explanation of the possible responses.
#
# At this point, you have an identity URL that you know belongs to
# the user who made that request.  Some sites will use that URL
# directly as the user name.  Other sites will want to map that URL
# to a username in the site's traditional namespace.  At this point,
# you can take whichever action makes the most sense.
#
# CONSTANTS
# =========
#
# SUCCESS: This is the status code returned when either the of the
#    OpenID::OpenIDConsumer.beginAuth or OpenID::OpenIDConsuemr.completeAuth
#    methods return successfully.
#
# HTTP_FAILURE: This is the status code OpenID::OpenIDConsumer.beginAuth
#    returns when it is unable to fetch the OpenID URL the user
#    entered.
#
# PARSE_ERROR: This is the status code OpenID::OpenIDConsumer.beginAuth
#    returns when the page fetched from the entered OpenID URL doesn't
#    contain the necessary link tags to function as an identity page.
#
# FAILURE: This is the status code OpenID::OpenIDConsumer.completeAuth
#    returns when the value it received indicated an invalid login.
#
# SETUP_NEEDED: This is the status code OpenID::OpenIDConsumer.completeAuth
#    returns when the C{L{OpenIDConsumer}} instance is in immediate
#    mode, and the identity server sends back a URL to send the user to
#    to complete his or her login.
#
require "openid/consumer/fetchers"
require "openid/consumer/impl"

module OpenID

  SUCCESS = 'success'
  FAILURE = 'failure'
  SETUP_NEEDED = 'setup needed'  
  HTTP_FAILURE = 'http failure'
  PARSE_ERROR = 'parse error'

  # OpenIDConsumer is the interface to the OpenID consumer logic.
  # Instances of it maintain no per-request state, so they can be
  # reused (or even used by multiple threads concurrently) as needed.
  #
  # It's instance var "impl" is the backing instance which actually implements
  # the logic behind the methods in this class.  The primary
  # reason you might ever care about this is if you have a problem
  # with the tokens generated by this library expiring in two
  # minutes.  If you set TOKEN_LIFETIME attribute on impl,
  # it will be used as the number of seconds before the generated
  # tokens are no longer considered valid.  The default value of
  # two minutes is probably fine in most cases, but if it's not,
  # it can be altered easily.
  #
  # Param: store argument to initialize must be an object that implements the
  # interface in openid/consumer/stores.rb
  # For a filesystem-backed store, see the openid/consumer/filestore.rb.
  #
  # As a last resort, if it isn't possible for the server to
  # store state at all, an instance of OpenID::DumbStore can be used.  This
  # should be an absolute last resort, though, as it makes the
  # consumer vulnerable to replay attacks over the lifespan of
  # the tokens the library creates.  See impl for
  # information on controlling the lifespan of those tokens.
  #
  # Param: fetcher: an optional instance of
  # OpenID::OpenIDHTTPFetcher.  If present, the provided
  # fetcher is used by the library to
  # fetch user's identity pages and make direct requests to
  # the identity server.  If it is not present, a default
  # fetcher is used.  The default fetcher uses ruby's net/http
  # library.
  #  
  # Param: immediate: an optional boolean value.  It
  # controls whether the library uses immediate mode, as
  # explained in the module description.  The default value is
  # false, which disables immediate mode.
  
  class OpenIDConsumer

    def initialize(store, fetcher=nil, immediate=false)    
      if fetcher.nil?
        fetcher = NetHTTPFetcher.new
      end
    
      @impl = OpenIDConsumerImpl.new(store, immediate, fetcher)
    end
    
    # beginAuth is called to start the OpenID login process.
    #
    # First, the user's claimed identity page is fetched, to
    # determine their identity server.  If the page cannot 
    # fetched or if the page does not have the necessary link tags
    # in it, this method returns one of HTTP_FAILURE or
    # PARSE_ERROR, depending on where the process failed.
    #
    # Second, unless the store provided is a dumb store, it checks
    # to see if it has an association with that identity server, and
    # creates and stores one if not.
    #
    # Third, it generates a signed token for this authentication
    # transaction, which contains a timestamp, a nonce, and the
    # information needed in step 4 in the OpenIDConsumer overview.
    # The token is used by the library to make handling the various
    # pieces of information needed in step 4 easy and secure.
    #
    # The token generated must be preserved until step 4, which is
    # after the redirect to the OpenID server takes place.  This
    # means that the token must be preserved across http requests. 
    # There are three basic approaches that might be used for storing
    # the token.  First, the token could be put in the return_to URL
    # passed into the constructRedirect method.  Second, the token could be
    # stored in a cookie.  Third, in an environment that supports
    # user sessions, the session is a good spot to store the token.
    #
    # Param: user_url: The url the user entered as their
    #        OpenID.  This call takes care of normalizing it and
    #        resolving any redirects the server might issue. 
    #
    # Return: This method returns an array of two elements: status code
    #         and additional information about the code.
    #
    #        If there was a problem fetching the identity page the user
    #        gave, the status code is set to HTTP_FAILURE, and
    #        the additional information value is currently set to
    #        nil.  The additional information value may change in a
    #        future release.
    #
    #        If the identity page fetched successfully, but didn't
    #        include the correct link tags, the status code is set to
    #        PARSE_ERROR, and the additional information value is
    #        currently set to nil.  The additional information
    #        value may change in a future release.
    #
    #        Otherwise, the status code is set to SUCCESS, and
    #        the additional information is an instance of
    #        OpenID::OpenIDAuthRequest.  TheOpenIDAuthRequest.token 
    #        attribute contains the token to be preserved for the next
    #        HTTP request.  The OpenIDAuthRequest.server_url might also be
    #        of interest, if you wish to blacklist or whitelist OpenID
    #        servers.  The other contents of the object are information
    #        needed in the constructRedirect call.

    def beginAuth(user_url)
      @impl.beginAuth(user_url)
    end

    # constructRedirect is called to construct the redirect URL sent to
    # the browser to ask the server to verify its identity.  This is
    # called in L{step 3<openid.consumer.interface>} of the flow
    # described in the overview.  The generated redirect should be
    # sent to the browser which initiated the authorization request.
    #
    # Param: auth_request: This must be an OpenIDAuthRequest
    #        instance which was returned from a previous call to
    #        beginAuth.  It contains information found during the
    #        beginAuth call which is needed to build the redirect URL.
    #
    # Param: return_to: The URL that will be included in the
    #        generated redirect as the URL the OpenID server will send
    #        its response to.  The URL passed in must handle OpenID
    #        authentication responses.
    #
    # Param: trust_root: The URL that will be sent to the
    #        server to identify this site.  The OpenID
    #        spec(http://www.openid.net/specs.bml#mode-checkid_immediate)
    #        has more information on what the trust_root value is for
    #        and what its form can be.  While the trust root is
    #        officially optional in the OpenID specification, this
    #        implementation requires that it be set.  Nothing is
    #        actually gained by leaving out the trust root, as you can
    #        get identical behavior by specifying the return_to URL as
    #        the trust root.
    #
    # Return: This method returns a string containing the URL to
    #         redirect to when such a URL is successfully constructed.

    def constructRedirect(auth_request, return_to, trust_root)
      @impl.constructRedirect(auth_request, return_to, trust_root)
    end

    # This method is called to interpret the server's response to an
    # OpenID request.  It is called in step 4 of the flow described in the
    # overview.
    #
    # The return value is a pair, consisting of a status and
    # additional information.  The status values are strings, but
    # should be referred to by their symbolic values: SUCCESS,
    # FAILURE, and SETUP_NEEDED.
    #
    # When SUCCESS is returned, the additional information
    # returned is either nil or a String.  If it is nil, it
    # means the user cancelled the login, and no further information
    # can be determined.  If the additional information is a String,
    # it is the identity that has been verified as belonging to the
    # user making this request.
    #
    # When FAILURE is returned, the additional information is
    # either nil or a String.  In either case, this code means
    # that the identity verification failed.  If it can be
    # determined, the identity that failed to verify is returned.
    # Otherwise nil is returned.
    #
    # Param: token: the token for this authentication
    #        transaction, generated by the call beginAuth.
    # 
    # Param: query: This is a dictionary-like object containing the
    #        query parameters the OpenID server included in its
    #        redirect back to the return_to URL.  The keys and values
    #        should both be url-unescaped.
    #
    # @type query: a C{dict}-like object
    #
    #
    # @return: Returns the status of the response and any additional
    #        information, as described above.
    #
    #    @rtype: A pair, consisting of either two C{str} objects, or a
    #        C{str} and C{None}.

    def completeAuth(token, query)
      @impl.processServerResponse(token, query)
    end

  end

  # This class represents an in-progress OpenID authentication
  # request.  It exists to make transferring information between the
  # OpenIDConsumer.beginAuth and OpenIDConsumer.constructRedirect methods
  # easier.  Users of the OpenID consumer library will need to be
  # aware of the token value, and may care about the
  # server_url value.  All other fields are internal information
  # for the library which the user of the library shouldn't touch at
  # all.

  class OpenIDAuthRequest
    
    attr_reader :token, :server_id, :server_url, :nonce
    
    # Creates a new OpenIDAuthRequest object.  This just stores each
    # argument in an appropriately named field.
    #
    # Users of this library should not create instances of this
    # class.  Instances of this class are created by the library
    # when needed.
    
    def initialize(token, server_id, server_url, nonce)
      @token = token
      @server_id = server_id
      @server_url = server_url
      @nonce = nonce
    end
  end


end


