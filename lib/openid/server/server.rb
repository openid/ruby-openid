
require 'openid/cryptutil'
require 'openid/util'
require 'openid/dh'
require 'openid/store/nonce'
require 'openid/trustroot'
require 'openid/association'
require 'openid/message'

require 'time'

module OpenID

  module Server

    HTTP_OK = 200
    HTTP_REDIRECT = 302
    HTTP_ERROR = 400

    BROWSER_REQUEST_MODES = ['checkid_setup', 'checkid_immediate']

    ENCODE_KVFORM = ['kvform'].freeze
    ENCODE_URL = ['URL/redirect'].freeze
    ENCODE_HTML_FORM = ['HTML form'].freeze

    UNUSED = nil

    class OpenIDRequest
      attr_reader :mode
      attr_accessor :namespace, :message

      # I represent an incoming OpenID request.
      #
      # @cvar mode: the C{X{openid.mode}} of this request.
      # @type mode: str
      def initialize
        @mode = nil
      end
    end

    class CheckAuthRequest < OpenIDRequest
      # A request to verify the validity of a previous response.
      #
      # @cvar mode: "X{C{check_authentication}}"
      # @type mode: str
      #
      # @ivar assoc_handle: The X{association handle} the response was signed with.
      # @type assoc_handle: str
      # @ivar signed: The message with the signature which wants checking.
      # @type signed: L{Message}
      #
      # @ivar invalidate_handle: An X{association handle} the client is asking
      # about the validity of.  Optional, may be C{None}.
      # @type invalidate_handle: str
      #
      # @see: U{OpenID Specs, Mode: check_authentication
      # <http://openid.net/specs.bml#mode-check_authentication>}

      attr_accessor :assoc_handle, :signed, :invalidate_handle, :sig

      def initialize(assoc_handle, signed, invalidate_handle=nil)
        # Construct me.
        #
        # These parameters are assigned directly as class attributes,
        # see my L{class documentation<CheckAuthRequest>} for their
        # descriptions.
        #
        # @type assoc_handle: str
        # @type signed: L{Message}
        # @type invalidate_handle: str
        super()

        @mode = "check_authentication"
        @required_fields = ["identity", "return_to", "response_nonce"].freeze

        @assoc_handle = assoc_handle
        @signed = signed
        @invalidate_handle = invalidate_handle
        @namespace = OPENID2_NS
      end

      def self.from_message(message, op_endpoint=UNUSED)
        # Construct me from an OpenID Message.
        #
        # @param message: An OpenID check_authentication Message
        # @type message: L{openid.message.Message}
        #
        # @returntype: L{CheckAuthRequest}
        assoc_handle = message.get_arg(OPENID_NS, 'assoc_handle')
        invalidate_handle = message.get_arg(OPENID_NS, 'invalidate_handle')

        signed = message.copy()
        # openid.mode is currently check_authentication because
        # that's the mode of this request.  But the signature
        # was made on something with a different openid.mode.
        # http://article.gmane.org/gmane.comp.web.openid.general/537
        if signed.has_key?(OPENID_NS, "mode")
          signed.set_arg(OPENID_NS, "mode", "id_res")
        end

        obj = self.new(assoc_handle, signed, invalidate_handle)
        obj.message = message
        obj.namespace = message.get_openid_namespace()
        obj.sig = message.get_arg(OPENID_NS, 'sig')

        if !obj.assoc_handle or
            !obj.sig
          msg = sprintf("%s request missing required parameter from message %s",
                        obj.mode, message)
            raise ProtocolError.new(message, msg)
        end

        return obj
      end

      def answer(signatory)
        # Respond to this request.
        #
        # Given a L{Signatory}, I can check the validity of the
        # signature and the X{C{invalidate_handle}}.
        #
        # @param signatory: The L{Signatory} to use to check the signature.
        # @type signatory: L{Signatory}
        #
        # @returns: A response with an X{C{is_valid}} (and, if
        #    appropriate X{C{invalidate_handle}}) field.
        # @returntype: L{OpenIDResponse}
        is_valid = signatory.verify(@assoc_handle, @signed)
        # Now invalidate that assoc_handle so it this checkAuth
        # message cannot be replayed.
        signatory.invalidate(@assoc_handle, dumb=true)
        response = OpenIDResponse.new(self)
        valid_str = is_valid ? "true" : "false"
        response.fields.set_arg(OPENID_NS, 'is_valid', valid_str)

        if @invalidate_handle
          assoc = signatory.get_association(@invalidate_handle, dumb=false)
          if !assoc
            response.fields.set_arg(
                    OPENID_NS, 'invalidate_handle', @invalidate_handle)
          end
        end

        return response
      end

      def to_s
        ih = nil

        if @invalidate_handle
          ih = sprintf(" invalidate? %s", @invalidate_handle)
        else
          ih = ""
        end

        s = sprintf("<%s handle: %r sig: %r: signed: %r%s>",
                    self.class, @assoc_handle,
                    @sig, @signed, ih)
        return s
      end
    end

    class BaseServerSession
      attr_reader :session_type

      def initialize(session_type, allowed_assoc_types)
        @session_type = session_type
        @allowed_assoc_types = allowed_assoc_types.dup.freeze
      end

      def allowed_assoc_type?(typ)
        @allowed_assoc_types.member?(typ)
      end
    end

    class PlainTextServerSession < BaseServerSession
      attr_reader :session_type
      # An object that knows how to handle association requests with
      # no session type.
      #
      # @cvar session_type: The session_type for this association
      #   session. There is no type defined for plain-text in the OpenID
      #   specification, so we use 'no-encryption'.
      # @type session_type: str
      #
      # @see: U{OpenID Specs, Mode: associate
      # <http://openid.net/specs.bml#mode-associate>}
      # @see: AssociateRequest
      def initialize
        super('no-encryption', ['HMAC-SHA1', 'HMAC-SHA256'])
      end

      def self.from_message(unused_request)
        return self.new
      end

      def answer(secret)
        return {'mac_key' => Util.to_base64(secret)}
      end
    end

    class DiffieHellmanSHA1ServerSession < BaseServerSession
      # An object that knows how to handle association requests with the
      # Diffie-Hellman session type.
      #
      # @cvar session_type: The session_type for this association
      #   session.
      # @type session_type: str
      #
      # @ivar dh: The Diffie-Hellman algorithm values for this request
      # @type dh: DiffieHellman
      #
      # @ivar consumer_pubkey: The public key sent by the consumer in the
      #   associate request
      # @type consumer_pubkey: long
      #
      # @see: U{OpenID Specs, Mode: associate
      #   <http://openid.net/specs.bml#mode-associate>}
      # @see: AssociateRequest

      attr_accessor :dh, :consumer_pubkey
      attr_reader :session_type

      def initialize(dh, consumer_pubkey)
        super('DH-SHA1', ['HMAC-SHA1'])

        @hash_func = CryptUtil.method('sha1')
        @dh = dh
        @consumer_pubkey = consumer_pubkey
      end

      def self.from_message(message)
        # @param message: The associate request message
        # @type message: openid.message.Message
        #
        # @returntype: L{DiffieHellmanSHA1ServerSession}
        #
        # @raises ProtocolError: When parameters required to establish the
        #   session are missing.
        dh_modulus = message.get_arg(OPENID_NS, 'dh_modulus')
        dh_gen = message.get_arg(OPENID_NS, 'dh_gen')
        if (!dh_modulus and dh_gen or
            !dh_gen and dh_modulus)

          if !dh_modulus
            missing = 'modulus'
          else
            missing = 'generator'
          end

          raise ProtocolError.new(message,
                  sprintf('If non-default modulus or generator is ' +
                          'supplied, both must be supplied. Missing %s',
                          missing))
        end

        if dh_modulus or dh_gen
          dh_modulus = CryptUtil.base64_to_num(dh_modulus)
          dh_gen = CryptUtil.base64_to_num(dh_gen)
          dh = DiffieHellman.new(dh_modulus, dh_gen)
        else
          dh = DiffieHellman.from_defaults()
        end

        consumer_pubkey = message.get_arg(OPENID_NS, 'dh_consumer_public')
        if !consumer_pubkey
          raise ProtocolError.new(message,
                  sprintf("Public key for DH-SHA1 session " +
                          "not found in message %s", message))
        end

        consumer_pubkey = CryptUtil.base64_to_num(consumer_pubkey)

        return self.new(dh, consumer_pubkey)
      end

      def answer(secret)
        mac_key = @dh.xor_secret(@hash_func,
                                 @consumer_pubkey,
                                 secret)
        return {
            'dh_server_public' => CryptUtil.num_to_base64(@dh.public),
            'enc_mac_key' => Util.to_base64(mac_key),
            }
      end
    end

    class DiffieHellmanSHA256ServerSession < DiffieHellmanSHA1ServerSession
      def initialize(*args)
        super(*args)
        @session_type = 'DH-SHA256'
        @hash_func = CryptUtil.method('sha256')
        @allowed_assoc_types = ['HMAC-SHA256'].freeze
      end
    end

    class AssociateRequest < OpenIDRequest
      # A request to establish an X{association}.
      #
      # @cvar mode: "X{C{check_authentication}}"
      # @type mode: str
      #
      # @ivar assoc_type: The type of association.  The protocol currently only
      #   defines one value for this, "X{C{HMAC-SHA1}}".
      # @type assoc_type: str
      #
      # @ivar session: An object that knows how to handle association
      #   requests of a certain type.
      #
      # @see: U{OpenID Specs, Mode: associate
      #   <http://openid.net/specs.bml#mode-associate>}
      attr_accessor :session, :assoc_type

      @@session_classes = {
        'no-encryption' => PlainTextServerSession,
        'DH-SHA1' => DiffieHellmanSHA1ServerSession,
        'DH-SHA256' => DiffieHellmanSHA256ServerSession,
      }

      def initialize(session, assoc_type)
        # Construct me.
        #
        # The session is assigned directly as a class attribute. See
        # my L{class documentation<AssociateRequest>} for its
        # description.
        super()
        @session = session
        @assoc_type = assoc_type
        @namespace = OPENID2_NS

        @mode = "associate"
      end

      def self.from_message(message, op_endpoint=UNUSED)
        # Construct me from an OpenID Message.
        #
        # @param message: The OpenID associate request
        # @type message: openid.message.Message
        #
        # @returntype: L{AssociateRequest}
        if message.is_openid1()
          session_type = message.get_arg(OPENID1_NS, 'session_type')
          if session_type == 'no-encryption'
            Util.log('Received OpenID 1 request with a no-encryption ' +
                     'assocaition session type. Continuing anyway.')
          elsif !session_type
            session_type = 'no-encryption'
          end
        else
          session_type = message.get_arg(OPENID2_NS, 'session_type')
          if !session_type
            raise ProtocolError.new(message,
                                    text="session_type missing from request")
          end
        end

        session_class = @@session_classes[session_type]

        if !session_class
          raise ProtocolError.new(message,
                  sprintf("Unknown session type %s", session_type))
        end

        begin
          session = session_class.from_message(message)
        rescue ArgumentError => why
          # XXX
          raise ProtocolError.new(message,
                                  sprintf('Error parsing %s session: %s',
                                          session_type, why))
        end

        assoc_type = message.get_arg(OPENID_NS, 'assoc_type', 'HMAC-SHA1')
        if !session.allowed_assoc_type?(assoc_type)
          msg = sprintf('Session type %s does not support association type %s',
                        session_type, assoc_type)
          raise ProtocolError.new(message, msg)
        end

        obj = self.new(session, assoc_type)
        obj.message = message
        obj.namespace = message.get_openid_namespace()
        return obj
      end

      def answer(assoc)
        # Respond to this request with an X{association}.
        #
        # @param assoc: The association to send back.
        # @type assoc: L{openid.association.Association}
        #
        # @returns: A response with the association information, encrypted
        #     to the consumer's X{public key} if appropriate.
        # @returntype: L{OpenIDResponse}
        response = OpenIDResponse.new(self)
        response.fields.update_args(OPENID_NS, {
            'expires_in' => sprintf('%d', assoc.expires_in()),
            'assoc_type' => @assoc_type,
            'assoc_handle' => assoc.handle,
            })
        response.fields.update_args(OPENID_NS,
                                   @session.answer(assoc.secret))
        if @session.session_type != 'no-encryption'
          response.fields.set_arg(
              OPENID_NS, 'session_type', @session.session_type)
        end

        return response
      end

      def answer_unsupported(message, preferred_association_type=nil,
                             preferred_session_type=nil)
        # Respond to this request indicating that the association type
        # or association session type is not supported.
        if @message.is_openid1()
          raise ProtocolError.new(@message)
        end

        response = OpenIDResponse.new(self)
        response.fields.set_arg(OPENID_NS, 'error_code', 'unsupported-type')
        response.fields.set_arg(OPENID_NS, 'error', message)

        if preferred_association_type
          response.fields.set_arg(
              OPENID_NS, 'assoc_type', preferred_association_type)
        end

        if preferred_session_type
          response.fields.set_arg(
              OPENID_NS, 'session_type', preferred_session_type)
        end

        return response
      end
    end

    class CheckIDRequest < OpenIDRequest
      # A request to confirm the identity of a user.
      #
      # This class handles requests for openid modes
      # X{C{checkid_immediate}} and X{C{checkid_setup}}.
      #
      # @cvar mode: "X{C{checkid_immediate}}" or "X{C{checkid_setup}}"
      # @type mode: str
      #
      # @ivar immediate: Is this an immediate-mode request?
      # @type immediate: bool
      #
      # @ivar identity: The OP-local identifier being checked.
      # @type identity: str
      #
      # @ivar claimed_id: The claimed identifier.  Not present in OpenID 1.x
      # messages.
      # @type claimed_id: str
      #
      # @ivar trust_root: "Are you Frank?" asks the checkid request.
      # "Who wants to know?"  C{trust_root}, that's who.  This URL
      # identifies the party making the request, and the user will use
      # that to make her decision about what answer she trusts them to
      # have.  Referred to as "realm" in OpenID 2.0.
      # @type trust_root: str
      #
      # @ivar return_to: The URL to send the user agent back to to
      # reply to this request.
      # @type return_to: str
      #
      # @ivar assoc_handle: Provided in smart mode requests, a handle
      # for a previously established association.  C{None} for dumb
      # mode requests.
      # @type assoc_handle: str

      attr_accessor :assoc_handle, :identity, :claimed_id,
      :return_to, :trust_root, :op_endpoint, :immediate, :mode

      def initialize(identity, return_to, op_endpoint, trust_root=nil,
                     immediate=false, assoc_handle=nil)
        # Construct me.
        #
        # These parameters are assigned directly as class attributes,
        # see my L{class documentation<CheckIDRequest>} for their
        # descriptions.
        #
        # @raises MalformedReturnURL: When the C{return_to} URL is not
        # a URL.
        @namespace = OPENID2_NS
        @assoc_handle = assoc_handle
        @identity = identity
        @claimed_id = identity
        @return_to = return_to
        @trust_root = trust_root or return_to
        @op_endpoint = op_endpoint

        if immediate
          @immediate = true
          @mode = "checkid_immediate"
        else
          @immediate = false
          @mode = "checkid_setup"
        end

        if @return_to and
            !TrustRoot::TrustRoot.parse(@return_to)
          raise MalformedReturnURL.new(nil, @return_to)
        end

        if !trust_root_valid()
          raise UntrustedReturnURL.new(nil, @return_to, @trust_root)
        end
      end

      def self.from_message(message, op_endpoint)
        # Construct me from an OpenID message.
        #
        # @raises ProtocolError: When not all required parameters are present
        #     in the message.
        #
        # @raises MalformedReturnURL: When the C{return_to} URL is not
        # a URL.
        #
        # @raises UntrustedReturnURL: When the C{return_to} URL is
        # outside the C{trust_root}.
        #
        # @param message: An OpenID checkid_* request Message
        # @type message: openid.message.Message
        #
        # @param op_endpoint: The endpoint URL of the server that this
        # message was sent to.
        # @type op_endpoint: str
        #
        # @returntype: L{CheckIDRequest}
        obj = self.allocate
        obj.message = message
        obj.namespace = message.get_openid_namespace()
        obj.op_endpoint = op_endpoint
        mode = message.get_arg(OPENID_NS, 'mode')
        if mode == "checkid_immediate"
          obj.immediate = true
          obj.mode = "checkid_immediate"
        else
          obj.immediate = false
          obj.mode = "checkid_setup"
        end

        obj.return_to = message.get_arg(OPENID_NS, 'return_to')
        if obj.namespace == OPENID1_NS and !obj.return_to
          msg = sprintf("Missing required field 'return_to' from %s",
                        message)
          raise ProtocolError.new(message, msg)
        end

        obj.identity = message.get_arg(OPENID_NS, 'identity')
        if obj.identity and message.is_openid2()
          obj.claimed_id = message.get_arg(OPENID_NS, 'claimed_id')
          if !obj.claimed_id
            s = ("OpenID 2.0 message contained openid.identity but not " +
                 "claimed_id")
            raise ProtocolError.new(message, s)
          end
        else
          obj.claimed_id = nil
        end

        if !obj.identity and obj.namespace == OPENID1_NS
          s = "OpenID 1 message did not contain openid.identity"
          raise ProtocolError.new(message, s)
        end

        # There's a case for making self.trust_root be a TrustRoot
        # here.  But if TrustRoot isn't currently part of the "public"
        # API, I'm not sure it's worth doing.
        if obj.namespace == OPENID1_NS
          obj.trust_root = message.get_arg(
                OPENID_NS, 'trust_root', obj.return_to)
        else
          obj.trust_root = message.get_arg(
                OPENID_NS, 'realm', obj.return_to)

          if !obj.return_to and
              !obj.trust_root
            raise ProtocolError.new(message, "openid.realm required when " +
                                    "openid.return_to absent")
          end
        end

        obj.assoc_handle = message.get_arg(OPENID_NS, 'assoc_handle')

        # Using TrustRoot.parse here is a bit misleading, as we're not
        # parsing return_to as a trust root at all.  However, valid
        # URLs are valid trust roots, so we can use this to get an
        # idea if it is a valid URL.  Not all trust roots are valid
        # return_to URLs, however (particularly ones with wildcards),
        # so this is still a little sketchy.
        if obj.return_to and \
          !TrustRoot::TrustRoot.parse(obj.return_to)
          raise MalformedReturnURL.new(message, obj.return_to)
        end

        # I first thought that checking to see if the return_to is
        # within the trust_root is premature here, a
        # logic-not-decoding thing.  But it was argued that this is
        # really part of data validation.  A request with an invalid
        # trust_root/return_to is broken regardless of application,
        # right?
        if !obj.trust_root_valid()
          raise UntrustedReturnURL.new(message, obj.return_to, obj.trust_root)
        end

        return obj
      end

      def id_select
        # Is the identifier to be selected by the IDP?
        #
        # @returntype: bool

        # So IDPs don't have to import the constant
        return @identity == IDENTIFIER_SELECT
      end

      def trust_root_valid
        # Is my return_to under my trust_root?
        # 
        # @returntype: bool
        if !@trust_root
          return true
        end

        tr = TrustRoot::TrustRoot.parse(@trust_root)
        if !tr
          raise MalformedTrustRoot.new(nil, @trust_root)
        end

        if @return_to
          return tr.validate_url(@return_to)
        else
          return true
        end
      end

      def return_to_verified
        # Does the relying party publish the return_to URL for this
        # response under the realm? It is up to the provider to set a
        # policy for what kinds of realms should be allowed. This
        # return_to URL verification reduces vulnerability to
        # data-theft attacks based on open proxies,
        # corss-site-scripting, or open redirectors.
        #
        # This check should only be performed after making sure that
        # the return_to URL matches the realm.
        #
        # @see: trustRootValid
        # 
        # @raises openid.yadis.discover.DiscoveryFailure: if the realm
        #     URL does not support Yadis discovery (and so does not
        #     support the verification process).
        #
        # @returntype: bool
        #
        # @returns: True if the realm publishes a document with the
        #     return_to URL listed
        return verify_return_to(@trust_root, @return_to)
      end

      def answer(allow, server_url=nil, identity=nil, claimed_id=nil)
        # Respond to this request.
        #
        # @param allow: Allow this user to claim this identity, and allow the
        #     consumer to have this information?
        # @type allow: bool
        #
        # @param server_url: DEPRECATED.  Passing C{op_endpoint} to the
        #     L{Server} constructor makes this optional.
        #
        #     When an OpenID 1.x immediate mode request does not
        #     succeed, it gets back a URL where the request may be
        #     carried out in a not-so-immediate fashion.  Pass my URL
        #     in here (the fully qualified address of this server's
        #     endpoint, i.e.  C{http://example.com/server}), and I
        #     will use it as a base for the URL for a new request.
        #
        #     Optional for requests where C{CheckIDRequest.immediate}
        #     is C{False} or C{allow} is C{True}.
        #
        # @type server_url: str
        #
        # @param identity: The OP-local identifier to answer with.  Only for use
        #     when the relying party requested identifier selection.
        # @type identity: str or None
        #
        # @param claimed_id: The claimed identifier to answer with,
        #     for use with identifier selection in the case where the
        #     claimed identifier and the OP-local identifier differ,
        #     i.e. when the claimed_id uses delegation.
        #
        #     If C{identity} is provided but this is not,
        #     C{claimed_id} will default to the value of C{identity}.
        #     When answering requests that did not ask for identifier
        #     selection, the response C{claimed_id} will default to
        #     that of the request.
        #
        #     This parameter is new in OpenID 2.0.
        # @type claimed_id: str or None
        #
        # @returntype: L{OpenIDResponse}
        #
        # @change: Version 2.0 deprecates C{server_url} and adds C{claimed_id}.

        # FIXME: undocumented exceptions
        if !@return_to
          raise NoReturnToError
        end

        if server_url
          if @namespace != OPENID1_NS and !@op_endpoint
            # In other words, that warning I raised in
            # Server.__init__?  You should pay attention to it now.
            raise RuntimeError.new(sprintf("%s should be constructed with op_endpoint " +
                                           "to respond to OpenID 2.0 messages.",
                                           self))
          end

          server_url = @op_endpoint
        end

        if allow
          mode = 'id_res'
        elsif @namespace == OPENID1_NS
          if @immediate
            mode = 'id_res'
          else
            mode = 'cancel'
          end
        else
          if @immediate
            mode = 'setup_needed'
          else
            mode = 'cancel'
          end
        end

        response = OpenIDResponse.new(self)

        if claimed_id and @namespace == OPENID1_NS
          raise VersionError.new(sprintf("claimed_id is new in OpenID 2.0 and not " +
                                         "available for %s", @namespace))
        end

        if identity and !claimed_id
          claimed_id = identity
        end

        if allow
          if @identity == IDENTIFIER_SELECT
            if !identity
              raise ValueError.new(
                      "This request uses IdP-driven identifier selection." +
                      "You must supply an identifier in the response.")
            end

            response_identity = identity
            response_claimed_id = claimed_id

          elsif @identity
            if identity and (@identity != identity)
              raise ValueError.new(
                sprintf("Request was for identity %s, cannot reply " +
                        "with identity %s", @identity, identity))
            end

            response_identity = @identity
            response_claimed_id = @claimed_id
          else
            if identity
              raise ValueError.new(
                sprintf("This request specified no identity and you " +
                        "supplied %s", identity))
            end
            response_identity = nil
          end

          if @namespace == OPENID1_NS and !response_identity
            raise ValueError.new(
                    "Request was an OpenID 1 request, so response must " +
                    "include an identifier.")
          end

          response.fields.update_args(OPENID_NS, {
                'mode' => mode,
                'op_endpoint' => server_url,
                'return_to' => @return_to,
                'response_nonce' => mkNonce(),
                })

          if response_identity
            response.fields.set_arg(
                  OPENID_NS, 'identity', response_identity)
            if @namespace == OPENID2_NS
              response.fields.set_arg(
                  OPENID_NS, 'claimed_id', response_claimed_id)
            end
          end
        else
          response.fields.set_arg(OPENID_NS, 'mode', mode)
          if @immediate
            if @namespace == OPENID1_NS and !server_url
              raise ValueError.new("setup_url is required for allow=false " +
                                   "in OpenID 1.x immediate mode.")
            end

            # Make a new request just like me, but with
            # immediate=False.
            setup_request = self.new(
                                     @identity, @return_to, @trust_root,
                                     immediate=false, assoc_handle=self.assoc_handle,
                                     op_endpoint=@op_endpoint)
            setup_url = setup_request.encodeToURL(server_url)
            response.fields.set_arg(OPENID_NS, 'user_setup_url', setup_url)
          end
        end

        return response
      end

      def encode_to_url(server_url)
        # Encode this request as a URL to GET.
        #
        # @param server_url: The URL of the OpenID server to make this
        # request of.
        #
        # @type server_url: str
        #
        # @returntype: str
        if !@return_to
          raise NoReturnToError
        end

        # Imported from the alternate reality where these classes are
        # used in both the client and server code, so Requests are
        # Encodable too.  That's right, code imported from alternate
        # realities all for the love of you, id_res/user_setup_url.
        q = {'mode' => @mode,
             'identity' => @identity,
             'claimed_id' => @claimed_id,
             'return_to' => @return_to}

        if @trust_root
          if @namespace == OPENID1_NS
            q['trust_root'] = @trust_root
          else
            q['realm'] = @trust_root
          end
        end

        if @assoc_handle
          q['assoc_handle'] = @assoc_handle
        end

        response = Message.new(@namespace)
        response.update_args(@namespace, q)
        return response.to_url(server_url)
      end

      def get_cancel_url
        # Get the URL to cancel this request.
        #
        # Useful for creating a "Cancel" button on a web form so that
        # operation can be carried out directly without another trip
        # through the server.
        #
        # (Except you probably want to make another trip through the
        # server so that it knows that the user did make a decision.
        # Or you could simulate this method by doing
        # C{.answer(False).encodeToURL()})
        #
        # @returntype: str
        # @returns: The return_to URL with openid.mode = cancel.
        if !@return_to
          raise NoReturnToError
        end

        if @immediate
          raise ValueError.new("Cancel is not an appropriate response to " +
                               "immediate mode requests.")
        end

        response = Message.new(@namespace)
        response.set_arg(OPENID_NS, 'mode', 'cancel')
        return response.to_url(@return_to)
      end

      def to_s
        return sprintf('<%s id:%r im:%s tr:%r ah:%r>', self.class,
                       @identity,
                       @immediate,
                       @trust_root,
                       @assoc_handle)
      end
    end

    class OpenIDResponse
      # I am a response to an OpenID request.
      #
      # @ivar request: The request I respond to.
      # @type request: L{OpenIDRequest}
      #
      # @ivar fields: My parameters as a dictionary with each key
      # mapping to one value.  Keys are parameter names with no
      # leading "C{openid.}". e.g.  "C{identity}" and "C{mac_key}",
      # never "C{openid.identity}".
      # @type fields: L{openid.message.Message}
      #
      # @ivar signed: The names of the fields which should be signed.
      # @type signed: list of str

      # Implementer's note: In a more symmetric client/server
      # implementation, there would be more types of OpenIDResponse
      # object and they would have validated attributes according to
      # the type of response.  But as it is, Response objects in a
      # server are basically write-only, their only job is to go out
      # over the wire, so this is just a loose wrapper around
      # OpenIDResponse.fields.

      attr_accessor :request, :fields

      def initialize(request)
        # Make a response to an L{OpenIDRequest}.
        #
        # @type request: L{OpenIDRequest}
        @request = request
        @fields = Message.new(request.namespace)
      end

      def to_s
        return sprintf("%s for %s: %s",
                       self.class,
                       @request.class,
                       @fields)
      end

      def to_form_markup
        # Returns the form markup for this response.
        #
        # @returntype: str
        return @fields.to_form_markup(
                 @fields.get_arg(OPENID_NS, 'return_to'))
      end

      def render_as_form
        # Returns True if this response's encoding is
        # ENCODE_HTML_FORM.  Convenience method for server authors.
        #
        # @returntype: bool
        return self.which_encoding == ENCODE_HTML_FORM
      end

      def needs_signing
        # Does this response require signing?
        #
        # @returntype: bool
        return @fields.get_arg(OPENID_NS, 'mode') == 'id_res'
      end

      # implements IEncodable

      def which_encoding
        # How should I be encoded?
        #
        # @returns: one of ENCODE_URL or ENCODE_KVFORM.
        if BROWSER_REQUEST_MODES.member?(@request.mode)
          if @fields.get_openid_namespace == OPENID2_NS and
              encode_to_url.length > OPENID1_URL_LIMIT
            return ENCODE_HTML_FORM
          else
            return ENCODE_URL
          end
        else
          return ENCODE_KVFORM
        end
      end

      def encode_to_url
        # Encode a response as a URL for the user agent to GET.
        #
        # You will generally use this URL with a HTTP redirect.
        #
        # @returns: A URL to direct the user agent back to.
        # @returntype: str
        return @fields.to_url(@request.return_to)
      end

      def add_extension(extension_response)
        # Add an extension response to this response message.
        #
        # @param extension_response: An object that implements the
        #     extension interface for adding arguments to an OpenID
        #     message.
        # @type extension_response: L{openid.extension}
        #
        # @returntype: None
        extension_response.to_message(@fields)
      end

      def encode_to_kvform
        # Encode a response in key-value colon/newline format.
        #
        # This is a machine-readable format used to respond to
        # messages which came directly from the consumer and not
        # through the user agent.
        #
        # @see: OpenID Specs,
        #    U{Key-Value Colon/Newline format<http://openid.net/specs.bml#keyvalue>}
        #
        # @returntype: str
        return @fields.to_kvform
      end

      def copy
        return Marshal.load(Marshal.dump(self))
      end
    end

    class WebResponse
      # I am a response to an OpenID request in terms a web server
      # understands.
      #
      # I generally come from an L{Encoder}, either directly or from
      # L{Server.encodeResponse}.
      #
      # @ivar code: The HTTP code of this response.
      # @type code: int
      #
      # @ivar headers: Headers to include in this response.
      # @type headers: dict
      #
      # @ivar body: The body of this response.
      # @type body: str

      attr_accessor :code, :headers, :body

      def initialize(code=HTTP_OK, headers=nil, body="")
        # Construct me.
        #
        # These parameters are assigned directly as class attributes,
        # see my L{class documentation<WebResponse>} for their
        # descriptions.
        @code = code
        if headers
          @headers = headers
        else
          @headers = {}
        end
        @body = body
      end
    end

    class Signatory
      # I sign things.
      #
      # I also check signatures.
      #
      # All my state is encapsulated in an
      # L{OpenIDStore<openid.store.interface.OpenIDStore>}, which
      # means I'm not generally pickleable but I am easy to
      # reconstruct.
      #
      # @cvar SECRET_LIFETIME: The number of seconds a secret remains valid.
      # @type SECRET_LIFETIME: int

      SECRET_LIFETIME = 14 * 24 * 60 * 60 # 14 days, in seconds

      # keys have a bogus server URL in them because the filestore
      # really does expect that key to be a URL.  This seems a little
      # silly for the server store, since I expect there to be only
      # one server URL.
      @@_normal_key = 'http://localhost/|normal'
      @@_dumb_key = 'http://localhost/|dumb'

      def self._normal_key
        @@_normal_key
      end

      def self._dumb_key
        @@_dumb_key
      end

      attr_accessor :store

      def initialize(store)
        # Create a new Signatory.
        #
        # @param store: The back-end where my associations are stored.
        # @type store: L{openid.store.interface.OpenIDStore}
        Util.assert(store)
        @store = store
      end

      def verify(assoc_handle, message)
        # Verify that the signature for some data is valid.
        # 
        # @param assoc_handle: The handle of the association used to sign the
        #   data.
        # @type assoc_handle: str
        #
        # @param message: The signed message to verify
        # @type message: openid.message.Message
        #
        # @returns: C{True} if the signature is valid, C{False} if not.
        # @returntype: bool
        assoc = get_association(assoc_handle, dumb=true)
        if !assoc
          Util.log(sprintf("failed to get assoc with handle %s to verify " +
                           "message %s", assoc_handle, message))
          return false
        end

        begin
          valid = assoc.check_message_signature(message)
        rescue ValueError => ex
          # XXX
          Util.log(sprintf("Error in verifying %s with %s: %s",
                           message, assoc, ex))
          return false
        end

        return valid
      end

      def sign(response)
        # Sign a response.
        #
        # I take a L{OpenIDResponse}, create a signature for
        # everything in its L{signed<OpenIDResponse.signed>} list, and
        # return a new copy of the response object with that signature
        # included.
        #
        # @param response: A response to sign.
        # @type response: L{OpenIDResponse}
        #
        # @returns: A signed copy of the response.
        # @returntype: L{OpenIDResponse}
        signed_response = response.copy
        assoc_handle = response.request.assoc_handle
        if assoc_handle
          # normal mode disabling expiration check because even if the
          # association is expired, we still need to know some
          # properties of the association so that we may preserve
          # those properties when creating the fallback association.
          assoc = get_association(assoc_handle, dumb=false,
                                  checkExpiration=false)

          if !assoc or assoc.expires_in <= 0
            # fall back to dumb mode
            signed_response.fields.set_arg(
                  OPENID_NS, 'invalidate_handle', assoc_handle)
            assoc_type = assoc ? assoc.assoc_type : 'HMAC-SHA1'
            if assoc and assoc.expires_in <= 0
              # now do the clean-up that the disabled checkExpiration
              # code didn't get to do.
              invalidate(assoc_handle, dumb=false)
              assoc = create_association(dumb=true, assoc_type=assoc_type)
            end
          end
        else
          # dumb mode.
          assoc = create_association(dumb=true)
        end

        signed_response.fields = assoc.sign_message(signed_response.fields)
        return signed_response
      end

      def create_association(dumb=true, assoc_type='HMAC-SHA1')
        # Make a new association.
        #
        # @param dumb: Is this association for a dumb-mode transaction?
        # @type dumb: bool
        #
        # @param assoc_type: The type of association to create.  Currently
        #     there is only one type defined, C{HMAC-SHA1}.
        # @type assoc_type: str
        #
        # @returns: the new association.
        # @returntype: L{openid.association.Association}
        secret = CryptUtil.random_string(OpenID.get_secret_size(assoc_type))
        uniq = Util.to_base64(CryptUtil.random_string(4))
        handle = sprintf('{%s}{%x}{%s}', assoc_type, Time.now.to_i, uniq)

        assoc = Association.from_expires_in(
            SECRET_LIFETIME, handle, secret, assoc_type)

        if dumb
          key = @@_dumb_key
        else
          key = @@_normal_key
        end

        @store.store_association(key, assoc)
        return assoc
      end

      def get_association(assoc_handle, dumb, checkExpiration=true)
        # Get the association with the specified handle.
        #
        # @type assoc_handle: str
        #
        # @param dumb: Is this association used with dumb mode?
        # @type dumb: bool
        #
        # @returns: the association, or None if no valid association with that
        #     handle was found.
        # @returntype: L{openid.association.Association}

        # Hmm.  We've created an interface that deals almost entirely
        # with assoc_handles.  The only place outside the Signatory
        # that uses this (and thus the only place that ever sees
        # Association objects) is when creating a response to an
        # association request, as it must have the association's
        # secret.

        if !assoc_handle
          raise ValueError.new("assoc_handle must not be None")
        end

        if dumb
          key = @@_dumb_key
        else
          key = @@_normal_key
        end

        assoc = @store.get_association(key, assoc_handle)
        if assoc and assoc.expires_in <= 0
          Util.log(sprintf("requested %sdumb key %r is expired (by %s seconds)",
                           (!dumb) ? 'not-' : '',
                           assoc_handle, assoc.expires_in))
          if checkExpiration
            @store.remove_association(key, assoc_handle)
            assoc = nil
          end
        end

        return assoc
      end

      def invalidate(assoc_handle, dumb)
        # Invalidates the association with the given handle.
        #
        # @type assoc_handle: str
        #
        # @param dumb: Is this association used with dumb mode?
        # @type dumb: bool
        if dumb
          key = @@_dumb_key
        else
          key = @@_normal_key
        end

        @store.remove_association(key, assoc_handle)
      end
    end

    class Encoder
      # I encode responses in to L{WebResponses<WebResponse>}.
      #
      # If you don't like L{WebResponses<WebResponse>}, you can do
      # your own handling of L{OpenIDResponses<OpenIDResponse>} with
      # L{OpenIDResponse.whichEncoding},
      # L{OpenIDResponse.encodeToURL}, and
      # L{OpenIDResponse.encodeToKVForm}.

      @@responseFactory = WebResponse

      def encode(response)
        # Encode a response to a L{WebResponse}.
        #
        # @raises EncodingError: When I can't figure out how to encode this
        # message.
        encode_as = response.which_encoding()
        if encode_as == ENCODE_KVFORM
          wr = @@responseFactory.new(HTTP_OK, nil,
                                     response.encode_to_kvform())
          if response.is_a?(Exception)
            wr.code = HTTP_ERROR
          end
        elsif encode_as == ENCODE_URL
          location = response.encode_to_url()
          wr = @@responseFactory.new(HTTP_REDIRECT,
                                     {'location' => location})
        elsif encode_as == ENCODE_HTML_FORM
          wr = @@responseFactory.new(HTTP_OK, nil,
                                     response.to_form_markup())
        else
          # Can't encode this to a protocol message.  You should
          # probably render it to HTML and show it to the user.
          raise EncodingError.new(response)
        end

        return wr
      end
    end

    class SigningEncoder < Encoder
      # I encode responses in to L{WebResponses<WebResponse>}, signing
      # them when required.

      attr_accessor :signatory

      def initialize(signatory)
        # Create a L{SigningEncoder}.
        #
        # @param signatory: The L{Signatory} I will make signatures with.
        # @type signatory: L{Signatory}
        @signatory = signatory
      end

      def encode(response)
        # Encode a response to a L{WebResponse}, signing it first if
        # appropriate.
        #
        # @raises EncodingError: When I can't figure out how to encode this
        #     message.
        #
        # @raises AlreadySigned: When this response is already signed.
        #
        # @returntype: L{WebResponse}

        # the isinstance is a bit of a kludge... it means there isn't
        # really an adapter to make the interfaces quite match.
        if !response.is_a?(Exception) and response.needs_signing()
          if !@signatory
            raise ArgumentError.new(
              sprintf("Must have a store to sign this request: %s",
                      response), response)
          end

          if response.fields.has_key?(OPENID_NS, 'sig')
            raise AlreadySigned.new(response)
          end

          response = @signatory.sign(response)
        end

        return super(response)
      end
    end

    class Decoder
      # I decode an incoming web request in to a L{OpenIDRequest}.

      @@handlers = {
        'checkid_setup' => CheckIDRequest.method('from_message'),
        'checkid_immediate' => CheckIDRequest.method('from_message'),
        'check_authentication' => CheckAuthRequest.method('from_message'),
        'associate' => AssociateRequest.method('from_message'),
        }

      attr_accessor :server

      def initialize(server)
        # Construct a Decoder.
        #
        # @param server: The server which I am decoding requests for.
        #     (Necessary because some replies reference their server.)
        # @type server: L{Server}
        @server = server
      end

      def decode(query)
        # I transform query parameters into an L{OpenIDRequest}.
        #
        # If the query does not seem to be an OpenID request at all, I
        # return C{None}.
        #
        # @param query: The query parameters as a dictionary with each
        #     key mapping to one value.
        # @type query: dict
        #
        # @raises ProtocolError: When the query does not seem to be a valid
        #     OpenID request.
        #
        # @returntype: L{OpenIDRequest}
        if query.nil? or query.length == 0
          return nil
        end

        message = Message.from_post_args(query)

        mode = message.get_arg(OPENID_NS, 'mode')
        if !mode
          msg = sprintf("No mode value in message %s", message)
          raise ProtocolError.new(message, msg)
        end

        handler = @@handlers.fetch(mode, self.method('default_decoder'))
        return handler.call(message, @server.op_endpoint)
      end

      def default_decoder(message, server)
        # Called to decode queries when no handler for that mode is
        # found.
        #
        # @raises ProtocolError: This implementation always raises
        #     L{ProtocolError}.
        mode = message.get_arg(OPENID_NS, 'mode')
        msg = sprintf("No decoder for mode %s", mode)
        raise ProtocolError.new(message, msg)
      end
    end

    class Server
      # I handle requests for an OpenID server.
      #
      # Some types of requests (those which are not C{checkid}
      # requests) may be handed to my L{handleRequest} method, and I
      # will take care of it and return a response.
      #
      # For your convenience, I also provide an interface to
      # L{Decoder.decode} and L{SigningEncoder.encode} through my
      # methods L{decodeRequest} and L{encodeResponse}.
      #
      # All my state is encapsulated in an
      # L{OpenIDStore<openid.store.interface.OpenIDStore>}, which
      # means I'm not generally pickleable but I am easy to
      # reconstruct.
      #
      # @ivar signatory: I'm using this for associate requests and to
      # sign things.
      # @type signatory: L{Signatory}
      #
      # @ivar decoder: I'm using this to decode things.
      # @type decoder: L{Decoder}
      #
      # @ivar encoder: I'm using this to encode things.
      # @type encoder: L{Encoder}
      #
      # @ivar op_endpoint: My URL.
      # @type op_endpoint: str
      #
      # @ivar negotiator: I use this to determine which kinds of
      # associations I can make and how.
      # @type negotiator: L{openid.association.SessionNegotiator}

      @@signatoryClass = Signatory
      @@encoderClass = SigningEncoder
      @@decoderClass = Decoder

      attr_accessor :store, :signatory, :encoder, :decoder, :negotiator,
      :op_endpoint

      def initialize(store, op_endpoint=nil)
        # A new L{Server}.
        #
        # @param store: The back-end where my associations are stored.
        # @type store: L{openid.store.interface.OpenIDStore}
        #
        # @param op_endpoint: My URL, the fully qualified address of this
        #     server's endpoint, i.e. C{http://example.com/server}
        # @type op_endpoint: str
        #
        # @change: C{op_endpoint} is new in library version 2.0.  It
        #     currently defaults to C{None} for compatibility with
        #     earlier versions of the library, but you must provide it
        #     if you want to respond to any version 2 OpenID requests.

        @store = store
        @signatory = @@signatoryClass.new(@store)
        @encoder = @@encoderClass.new(@signatory)
        @decoder = @@decoderClass.new(self)
        @negotiator = DefaultNegotiator.copy()

        if !op_endpoint
          Util.log("Server constructor requires op_endpoint parameter " +
                   "for OpenID 2.0 servers")
        end
        @op_endpoint = op_endpoint
      end

      def handle_request(request)
        # Handle a request.
        #
        # Give me a request, I will give you a response.  Unless it's
        # a type of request I cannot handle myself, in which case I
        # will raise C{NotImplementedError}.  In that case, you can
        # handle it yourself, or add a method to me for handling that
        # request type.
        #
        # @raises NotImplementedError: When I do not have a handler defined
        #     for that type of request.
        #
        # @returntype: L{OpenIDResponse}

        begin
          handler = self.method('openid_' + request.mode)
        rescue NameError
          raise RuntimeError.new(
            sprintf("%s has no handler for a request of mode %s.",
                    self, request.mode))
        end

        return handler.call(request)
      end

      def openid_check_authentication(request)
        # Handle and respond to C{check_authentication} requests.
        #
        # @returntype: L{OpenIDResponse}
        return request.answer(@signatory)
      end

      def openid_associate(request)
        # Handle and respond to C{associate} requests.
        #
        # @returntype: L{OpenIDResponse}

        # XXX: TESTME
        assoc_type = request.assoc_type
        session_type = request.session.session_type
        if @negotiator.is_allowed(assoc_type, session_type)
          assoc = @signatory.createAssociation(dumb=false,
                                               assoc_type=assoc_type)
          return request.answer(assoc)
        else
          message = sprintf('Association type %s is not supported with ' +
                            'session type %s', assoc_type, session_type)
          preferred_assoc_type, preferred_session_type = @negotiator.get_allowed_type()
          return request.answer_unsupported(message,
                                            preferred_assoc_type,
                                            preferred_session_type)
        end
      end

      def decode_request(query)
        # Transform query parameters into an L{OpenIDRequest}.
        #
        # If the query does not seem to be an OpenID request at all, I
        # return C{None}.
        #
        # @param query: The query parameters as a dictionary with each
        #     key mapping to one value.
        # @type query: dict
        #
        # @raises ProtocolError: When the query does not seem to be a valid
        #     OpenID request.
        #
        # @returntype: L{OpenIDRequest}
        #
        # @see: L{Decoder.decode}
        return @decoder.decode(query)
      end

      def encode_response(response)
        # Encode a response to a L{WebResponse}, signing it first if
        # appropriate.
        #
        # @raises EncodingError: When I can't figure out how to encode this
        #    message.
        #
        # @raises AlreadySigned: When this response is already signed.
        #
        # @returntype: L{WebResponse}
        #
        # @see: L{SigningEncoder.encode}
        return @encoder.encode(response)
      end
    end

    class ProtocolError < Exception
      # A message did not conform to the OpenID protocol.
      #
      # @ivar message: The query that is failing to be a valid OpenID
      # request.
      # @type message: openid.message.Message

      attr_accessor :openid_message, :reference, :contact

      def initialize(message, text=nil, reference=nil, contact=nil)
        # When an error occurs.
        #
        # @param message: The message that is failing to be a valid
        # OpenID request.
        # @type message: openid.message.Message
        #
        # @param text: A message about the encountered error.  Set as C{args[0]}.
        # @type text: str
        @openid_message = message
        @reference = reference
        @contact = contact
        Util.assert(!message.is_a?(String))
        super(text)
      end

      def get_return_to
        # Get the return_to argument from the request, if any.
        #
        # @returntype: str
        if @openid_message.nil?
          return false
        else
          return @openid_message.get_arg(OPENID_NS, 'return_to')
        end
      end

      def has_return_to
        # Did this request have a return_to parameter?
        #
        # @returntype: bool
        return !get_return_to().nil?
      end

      def to_message
        # Generate a Message object for sending to the relying party,
        # after encoding.
        namespace = @openid_message.get_openid_namespace()
        reply = Message.new(namespace)
        reply.set_arg(OPENID_NS, 'mode', 'error')
        reply.set_arg(OPENID_NS, 'error', self.to_s)

        if @contact
          reply.set_arg(OPENID_NS, 'contact', @contact.to_s)
        end

        if @reference
          reply.set_arg(OPENID_NS, 'reference', @reference.to_s)
        end

        return reply
      end

      # implements IEncodable

      def encode_to_url
        return to_message().to_url(get_return_to())
      end

      def encode_to_kvform
        return to_message().to_kvform()
      end

      def to_form_markup
        return to_message().to_form_markup(get_return_to())
      end

      def which_encoding
        # How should I be encoded?
        #
        # @returns: one of ENCODE_URL, ENCODE_KVFORM, or None.  If None,
        # I cannot be encoded as a protocol message and should be
        # displayed to the user.
        if has_return_to()
          if @openid_message.get_openid_namespace() == OPENID2_NS and
              encode_to_url().length > OPENID1_URL_LIMIT
            return ENCODE_HTML_FORM
          else
            return ENCODE_URL
          end
        end

        if @openid_message.nil?
          return nil
        end

        mode = @openid_message.get_arg(OPENID_NS, 'mode')
        if mode
          if !BROWSER_REQUEST_MODES.member?(mode)
            return ENCODE_KVFORM
          end
        end

        # According to the OpenID spec as of this writing, we are
        # probably supposed to switch on request type here (GET versus
        # POST) to figure out if we're supposed to print
        # machine-readable or human-readable content at this point.
        # GET/POST seems like a pretty lousy way of making the
        # distinction though, as it's just as possible that the user
        # agent could have mistakenly been directed to post to the
        # server URL.

        # Basically, if your request was so broken that you didn't
        # manage to include an openid.mode, I'm not going to worry too
        # much about returning you something you can't parse.
        return nil
      end
    end

    class VersionError < Exception
      # Raised when an operation was attempted that is not compatible
      # with the protocol version being used.
    end

    class NoReturnToError < Exception
      # Raised when a response to a request cannot be generated
      # because the request contains no return_to URL.
    end

    class EncodingError < Exception
      # Could not encode this as a protocol message.
      #
      # You should probably render it and show it to the user.
      #
      # @ivar response: The response that failed to encode.
      # @type response: L{OpenIDResponse}

      attr_reader :response

      def initialize(response)
        super(response)
        @response = response
      end
    end

    class AlreadySigned < EncodingError
      # This response is already signed.
    end

    class UntrustedReturnURL < ProtocolError
      # A return_to is outside the trust_root.

      attr_reader :return_to, :trust_root

      def initialize(message, return_to, trust_root)
        super(message)
        @return_to = return_to
        @trust_root = trust_root
      end

      def to_s
        return sprintf("return_to %s not under trust_root %s",
                       @return_to,
                       @trust_root)
      end
    end

    class MalformedReturnURL < ProtocolError
      attr_reader :return_to

      # The return_to URL doesn't look like a valid URL.
      def initialize(openid_message, return_to)
        @return_to = return_to
        super(openid_message)
      end
    end

    class MalformedTrustRoot < ProtocolError
      # The trust root is not well-formed.
      #
      # @see: OpenID Specs,
      # U{openid.trust_root<http://openid.net/specs.bml#mode-checkid_immediate>}
    end
  end
end
