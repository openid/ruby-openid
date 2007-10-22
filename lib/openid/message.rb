require 'openid/util'

module OpenID

  IDENTIFIER_SELECT = 'http://openid.net/identifier_select/2.0'

  # URI for Simple Registration extension, the only commonly deployed
  # OpenID 1.x extension, and so a special case.
  SREG_URI = 'http://openid.net/sreg/1.0'

  # The OpenID 1.x namespace URI
  OPENID1_NS = 'http://openid.net/sso/1.0'

  # The OpenID 2.0 namespace URI
  # XXX: not yet official
  OPENID2_NS = 'http://openid.net/specs/2.0/base'

  # The namespace consisting of pairs with keys that are prefixed with
  # "openid." but not in another namespace.
  NULL_NAMESPACE = :null_namespace

  # The null namespace, when it is an allowed OpenID namespace
  OPENID_NS = :openid_namespace

  # The top-level namespace, excluding all pairs with keys that start
  # with "openid."
  BARE_NS = :bare_namespace

  # Limit, in bytes, of identity provider and return_to URLs,
  # including response payload.  See OpenID 1.1 specification,
  # Appendix D.
  OPENID1_URL_LIMIT = 2047

  # All OpenID protocol fields.  Used to check namespace aliases.
  OPENID_PROTOCOL_FIELDS = [
                            'ns', 'mode', 'error', 'return_to',
                            'contact', 'reference', 'signed',
                            'assoc_type', 'session_type',
                            'dh_modulus', 'dh_gen',
                            'dh_consumer_public', 'claimed_id',
                            'identity', 'realm', 'invalidate_handle',
                            'op_endpoint', 'response_nonce', 'sig',
                            'assoc_handle', 'trust_root', 'openid',
                           ]

  # Raised if the generic OpenID namespace is accessed when there
  # is no OpenID namespace set for this message.
  class UndefinedOpenIDNamespace < Exception; end

  # Sentinel used for Message implementation to indicate that getArg
  # should raise an exception instead of returning a default.
  NO_DEFAULT = :no_default

  # Global namespace / alias registration map.  See
  # registerNamespaceAlias.
  REGISTERED_ALIASES = {}

  # Raised when an alias or namespace URI has already been registered.
  class NamespaceAliasRegistrationError < Exception; end

  # Registers a (namespace URI, alias) mapping in a global namespace
  # alias map.  Raises NamespaceAliasRegistrationError if either the
  # namespace URI or alias has already been registered with a
  # different value.  This function is required if you want to use a
  # namespace with an OpenID 1 message.
  def registerNamespaceAlias(namespace_uri, alias_)
    if REGISTERED_ALIASES.get(alias_) == namespace_uri
        return
    end

    if REGISTERED_ALIASES.values.include?(namespace_uri)
      raise NamespaceAliasRegistrationError,
        'Namespace uri #{namespace_uri} already registered'
    end

    if REGISTERED_ALIASES.member?(alias_)
      raise NamespaceAliasRegistrationError,
        'Alias #{alias_} already registered'
    end

    REGISTERED_ALIASES[alias_] = namespace_uri
  end

  class Message
    attr_reader :namespaces

    @@allowed_openid_namespaces = [OPENID1_NS, OPENID2_NS]

    def initialize(openid_namspace=nil)
      @args = {}
      @namespaces = NamespaceMap.new
      if openid_namspace
        self.set_openid_namespace(openid_namspace)
      else
        @openid_ns_uri = nil
      end
    end

    # Construct a Message containing a set of POST arguments.
    def Message.from_post_args(args)
      m = Message.new
      openid_args = {}
      args.each { |key,value|
        if value.is_a?(Array)
          raise ArgumentError, 'query hash must have one value for each key, not lists of values.'
        end

        prefix, rest = key.split('.', 2)
        if prefix.nil? or rest.nil?
          prefix = nil
          rest = nil
        end

        if prefix != 'openid'
          m.args[[BARE_NS,key].freeze] = value
        else
          openid_args[rest] = value
        end
      }

      m._from_openid_args(openid_args)
      return m
    end

    # Construct a Message from a parsed KVForm message.
    def Message.from_openid_args(openid_args)
      m = Message.new
      m._from_openid_args(openid_args)
      return m
    end

    def _from_openid_args(openid_args)
      ns_args = []

      # resolve namespaces
      openid_args.each { |rest, value|
        ns_alias, ns_key = rest.split('.', 2)
        if ns_alias.nil? or ns_key.nil?
          ns_alias = NULL_NAMESPACE
          ns_key = rest
        end

        if ns_alias == 'ns'
          @namespaces.add_alias(value, ns_key)
        elsif ns_alias == NULL_NAMESPACE and ns_key == 'ns'
          @namespaces.add_alias(value, NULL_NAMESPACE)
        else
          ns_args << [ns_alias, ns_key, value]
        end
      }

      # ensure that there is an OpenID namespace definition
      openid_ns_uri = @namespaces.get_namespace_uri(NULL_NAMESPACE)
      openid_ns_uri = OPENID1_NS unless openid_ns_uri

      self.set_openid_namespace(openid_ns_uri)

      # put the pairs into the appropriate namespaces
      ns_args.each { |ns_alias, ns_key, value|
        ns_uri = @namespaces.get_namespace_uri(ns_alias)
        unless ns_uri
          # only try to map an alias to a default if it's an
          # OpenID 1.x namespace
          REGISTERED_ALIASES.each { |_alias, _uri|
            if _alias == ns_alias
              ns_uri = _uri
              break
            end
          }

          unless ns_uri
            ns_uri = openid_ns_uri
            ns_key = "#{ns_alias}.#{ns_key}"
          else
            @namespaces.add_alias(ns_uri, ns_alias)
          end
        end
        self.set_arg(ns_uri, ns_key, value)
      }
    end

    def set_openid_namespace(openid_ns_uri)
      if !@@allowed_openid_namespaces.include?(openid_ns_uri)
        raise ArgumentError, "Invalid null namespace: #{openid_ns_uri}"
      end
      @namespaces.add_alias(openid_ns_uri, NULL_NAMESPACE)
      @openid_ns_uri = openid_ns_uri
    end

    def get_openid_namespace
      return @openid_ns_uri
    end

    def is_openid1
      return @openid_ns_uri == OPENID1_NS
    end

    def is_openid2
      return @openid_ns_uri == OPENID2_NS
    end

    # Create a message from a KVForm string
    def Message.from_kvform(kvform_string)
      return Message.from_openid_args(Util.parsekv(kvform_string))
    end

    def copy
      return Marshal.load(Marshal.dump(self))
    end

    # Return all arguments with "openid." in from of namespaced arguments.
    def to_post_args
      args = {}

      # add namespace defs to the output
      @namespaces.each { |ns_uri, ns_alias|
        if ns_alias == NULL_NAMESPACE
          if ns_uri != OPENID1_NS
            args['openid.ns'] = ns_uri
          end
        else
          if self.getOpenIDNamespace() != OPENID1_NS
            ns_key = 'openid.ns.' + ns_alias
            args[ns_key] = ns_uri
          end
        end
      }

      @args.each { |k, value|
        ns_uri, ns_key = k
        key = self.get_key(ns_uri, ns_key)
        args[key] = value
      }

      return args
    end

    # Return all namespaced arguments, failing if any non-namespaced arguments
    # exist.
    def to_args
      post_args = self.to_post_args
      kvargs = {}
      post_args.each { |k,v|
        if !k.starts_with?('openid.')
          raise ArgumentError, "This message can only be encoded as a POST, because it contains arguments that are not prefixed with 'openid.'"
        else
          kvargs[k[7..-1]] = v
        end
      }
      return kvargs
    end

    # Generate HTML form markup that contains the values in this
    # message, to be HTTP POSTed as x-www-form-urlencoded UTF-8.
    def to_form_markup(action_url, form_tag_attrs=nil, submit_text='Continue')
      form_tag_attr_map = {}

      if form_tag_attrs
        form_tag_attrs.each { |name, attr|
          form_tag_attr_map[name] = attr
        }
      end

      form_tag_attr_map['action'] = action_url
      form_tag_attr_map['method'] = 'post'
      form_tag_attr_map['accept-charset'] = 'UTF-8'
      form_tag_attr_map['enctype'] = 'application/x-www-form-urlencoded'

      markup = "<form "

      form_tag_attr_map.each { |k, v|
        markup += " #{k}=\"#{v}\""
      }

      markup += ">\n"

      to_post_args.each { |k,v|
        markup += "<input type='hidden' name='#{k}' value='#{v}' />\n"
      }
      markup += "<input type='submit' value='#{submit_text}' />\n"
      markup += "\n</form>"
      return markup
    end

    # Generate a GET URL with the paramters in this message attacked as
    # query parameters.
    def to_url(base_url)
      return Util.append_args(base_url, self.to_post_args)
    end

    # Generate a KVForm string that contains the parameters in this message.
    # This will fail is the message contains arguments outside of the
    # "openid." prefix.
    def to_kvform
      return Util.kvform(self.to_args)
    end

    # Generate an x-www-urlencoded string.
    def to_url_encoded
      args = self.to_post_args.map.sort
      return Util.urlencode(args)
    end

    # Convert an input value into the internally used values of this obejct.
    def _fix_ns(namespace)
      if namespace == OPENID_NS
        unless @openid_ns_uri
          raise UndefinedOpenIDNamespace, 'OpenID namespace not set'
        else
          namespace = @openid_ns_uri
        end
      end

      if namespace != BARE_NS and namespace.class != String
        raise ArgumentError, "Namespace must be BARE_NS, OPENID_NS or a string. Got #{namespace}"
      end

      if namespace != BARE_NS and namespace.index(':').nil? and namespace == 'sreg'
        msg = "OpenID 2.0 namespace identifiers SHOULD be URIs. Got #{namespace}"
        warn(msg)

        if namespace == 'sreg'
          msg = "Using #{SREG_URI} instead of \"sreg\" as namespace"
          warn(msg)
          return SREG_URI
        end
      end

      return namespace
    end

    def has_key?(namespace, ns_key)
      namespace = self._fix_ns(namespace)
      return @args.member?([namespace, ns_key])
    end

    # Get the key for a particular namespaced argument
    def get_key(namespace, ns_key)
      namespace = self._fix_ns(namespace)
      return ns_key if namespace == BARE_NS

      ns_alias = @namespaces.get_alias(namespace)

      # no alias is defined, so no key can exist
      return nil if ns_alias.nil?

      if ns_alias == NULL_NAMESPACE
        tail = ns_key
      else
        tail = "#{ns_alias}.#{ns_key}"
      end

      return 'openid.' + tail
    end

    # Get a value for a namespaced key.
    def get_arg(namespace, key, default=nil)
      namespace = self._fix_ns(namespace)
      @args.fetch([namespace, key]) {
        if default == NO_DEFAULT
          raise IndexError
        else
          default
        end
      }
    end

    # Get the arguments that are defined for this namespace URI.
    def get_args(namespace)
      namespace = self._fix_ns(namespace)
      args = {}
      @args.each { |k,v|
        pair_ns, ns_key = k
        args[ns_key] = v if pair_ns == namespace
      }
      return args
    end

    # Set multiple key/value pairs in one call.
    def update_args(namespace, updates)
      namespace = self._fix_ns(namespace)
      updates.each {|k,v| self.set_arg(namespace, k, v)}
    end

    # Set a single argument in this namespace
    def set_arg(namespace, key, value)
      namespace = self._fix_ns(namespace)
      @args[[namespace, key].freeze] = value
      if namespace != BARE_NS
        @namespaces.add(namespace)
      end
    end

    # Remove a single argument from this namespace.
    def del_arg(namespace, key)
      namespace = self._fix_ns(namespace)
      _key = [namespace, key]
      @args.delete(_key)
    end

    def eql?(other)
      return @args == other.args
    end

    def get_aliased_arg(aliased_key, default=nil)
      if aliased_key == 'ns'
        return get_openid_namespace()
      end

      if aliased_key.starts_with?('ns.')
        uri = @namespaces.get_namespace_uri(aliased_key[3..-1])
        return (uri.nil? ? default : uri)
      end

      alias_, key = aliased_key.split('.', 2)
      if key.nil?
        key = aliased_key
        ns = nil
      else
        ns = @namespaces.get_namespace_uri(alias_)
        p ns, key
      end

      if ns.nil?
        key = aliased_key
        ns = get_openid_namespace
      end

      return get_arg(ns, key, default)
    end
  end


  # Maintains a bidirectional map between namespace URIs and aliases.
  class NamespaceMap

    # Namespaces that should use a certain alias (for backwards-
    # compatability or beauty). If a URI in this hash is added to the
    # namespace map without an explicit desired name,
    # it will default to the value supplied here.
    @@default_aliases = {SREG_URI => 'sreg'}

    def initialize
      @alias_to_namespace = {}
      @namespace_to_alias = {}
    end

    def get_alias(namespace_uri)
      @namespace_to_alias[namespace_uri]
    end

    def get_namespace_uri(namespace_alias)
      @alias_to_namespace[namespace_alias]
    end

    # Add an alias from this namespace URI to the alias.
    def add_alias(namespace_uri, desired_alias)
      # Check that desired_alias is not an openid protocol field as
      # per the spec.
      assert(!OPENID_PROTOCOL_FIELDS.include?(desired_alias),
             "#{desired_alias} is not an allowed namespace alias")

      # check that there is not a namespace already defined for the
      # desired alias
      current_namespace_uri = @alias_to_namespace.fetch(desired_alias, nil)
      if current_namespace_uri and current_namespace_uri != namespace_uri
        raise IndexError, "Cannot map #{namespace_uri} to alias #{desired_alias}. #{current_namespace_uri} is already mapped to alias #{desired_alias}"
      end

      # Check that desired_alias does not contain a period as per the
      # spec.
      if desired_alias.is_a?(String)
          assert(desired_alias.index('.').nil?,
                 "#{desired_alias} must not contain a dot")
      end

      # check that there is not already a (different) alias for this
      # namespace URI.
      _alias = @namespace_to_alias[namespace_uri]
      if _alias and _alias != desired_alias
        raise IndexError, "Cannot map #{namespace_uri} to alias #{desired_alias}. It is already mapped to alias #{_alias}"
      end

      @alias_to_namespace[desired_alias] = namespace_uri
      @namespace_to_alias[namespace_uri] = desired_alias
      return desired_alias
    end

    # Add this namespace URI to the mapping, without caring what alias
    # it ends up with.
    def add(namespace_uri)
      # see if this namepace is already mapped to an alias
      _alias = @namespace_to_alias[namespace_uri]
      return _alias if _alias

      # see if there is a default alias for this namespace
      default_alias = @@default_aliases[namespace_uri]
      if default_alias
        begin
          self.add_alias(namespace_uri, default_alias)
        rescue IndexError
          nil
        else
          return default_alias
        end
      end

      # Fall back to generating a numberical alias
      i = 0
      while true
        _alias = 'ext' + i.to_s
        begin
          self.add_alias(namespace_uri, _alias)
        rescue IndexError
          i += 1
        else
          return _alias
        end
      end

      raise StandardError, 'Unreachable'
    end

    def defined?(namespace_uri)
      @namespace_to_alias.has_key?(namespace_uri)
    end
    alias :contains? :defined?

    def each
      @namespace_to_alias.each {|k,v| yield k,v}
    end

    def iter_namespace_uris
      # Return an iterator over the namespace URIs
      return @namespace_to_alias.keys()
    end

    def iter_aliases
      # Return an iterator over the aliases
      return @alias_to_namespace.keys()
    end

    def isDefined(namespace_uri)
      return @namespace_to_alias.member?(namespace_uri)
    end
  end
end
