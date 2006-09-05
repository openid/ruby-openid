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
  
  # Raised if the generic OpenID namespace is accessed when there
  # is no OpenID namespace set for this message.
  class UndefinedOpenIDNamespace < Exception; end
  
  class Message
    
    @@default_namesapaces = {
      'sreg': SREG_URI
    }

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
        if value.is_a? Array
          raise ArgumentError, 'query hash must have one value for each key, not lists of values.'
        end
        
        prefix, rest = key.split('.', 2)

        if prefix != 'openid'
          @args[[BARE_NS,key].freeze] = value
        else
          openid_args[rest] = value
        end
      }
      
      m.from_openid_args(openid_args)
      return m
    end

    # Construct a Message from a parsed KVForm message.
    def Message.from_openid_args(openid_args)
      m = Message.new
      m.from_openid_args(openid_args)
      return m
    end

    def from_openid_args(openid_args)
      ns_args = []
      
      # resolve namespaces
      openid_args.each { |rest, value|
        ns_alias, ns_key = rest.split('.', 2)
        # XXX: check port ValueError

        if ns_alias == 'ns'
          @namespaces.add_alias(value, ns_key)
        elsif ns_alias == NULL_NAMESPACE and ns_key == 'ns'
          @namespaces.add_alias(value, NULL_NAMESPACE)
        else
          ns_args << [ns_alias, ns_key, value].freeze
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
          if openid_ns_uri == OPENID1_NS
            ns_uri = @@default_namesapaces.fetch(ns_alias)
          end

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
      if !self.allowed_openid_namespaces.include?(openid_ns_uri)
        raise ArgumentError, "Invalid null namespace: #{openid_ns_uri}"
      end
      @namespaces.add_alias(openid_ns_uri, NULL_NAMESPACE)
      @openid_ns_uri = openid_ns_uri
    end

    def get_openid_namespace
      return @openid_ns_uri
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
          ns_key = 'openid.ns.' + ns_alias
          args[ns_key] = value
        end
      }

      args.each { |(ns_uri, ns_key), value|
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
      markup = "<form action='#{action_url}' method='POST' enctype='application/x-www-form-url-encoded' accept-charset='UTF-8'>\n"

      self.to_post_args.each { |k,v|
        markup += "<input type='hidden' name='#{k}' value='#{v}' />\n"
      }
      markup += "<input type='submit' value='#{submit_text}' />\n"
      markup += "\n</form>"
      return markup
    end

    # Generate a GET URL with the paramters in this message attacked as
    # query parameters.
    def to_URL(base_url)
      return Util.append_args(base_url, self.to_post_args)
    end

    # Generate a KVForm string that contains the parameters in this message.
    # This will fail is the message contains arguments outside of the 
    # "openid." prefix.
    def to_kvform
      return Util.kvform(self.to_args)
    end
    
    # Generate an x-www-urlencoded string.
    def to_URL_encoded
      args = self.to_post_args.map.sort
      return Util.urlencoded(args)
    end

    # Convert an input value into the internally used values of this obejct.
    def fix_ns(namespace)
      if namespace == OPENID_NS
        unless @openid_ns_uri
          raise UndefinedOpenIDNamespace, 'OpenID namespace not set'
        else
          namespace = @openid_ns_uri
        end
      end

      if namespace != BARE_NS and namespace.class != String
        raise ArgumentError, "Namespace must be BARE_NS, OPENID_NS or a string. Got #{namespace}".
      end
      
      if namespace != BARE_NS and namespace.index(':').nil?
        return SREG_URI if namespace == 'sreg'
      end

      return namespace
    end

    def has_key?(namespace, ns_key)
      namespace = self.fix_ns(namespace)
      return @args.member?([namespace, ns_key])
    end

    # Get the key for a particular namespaced argument
    def get_key(namespace, ns_key)
      namespace = self.fix_ns(namespace)
      return ns_key if namespace == BARE_NS

      ns_alias = @namespaces.get_alias(namespace)
      
      # no alias is defined, so no key can exist
      return nil unless ns_alias

      if ns_alias == NULL_NAMESPACE
        tail = ns_key
      else
        tail = "#{ns_alias}.#{ns_key}"
      end
      
      return 'openid.' + tail
    end

    # Get a value for a namespaced key.
    def get_arg(namespace, key, defualt=nil)
      namespace = self.fix_ns(namespace)
      return @args.fetch([namespace,key], defualt)
    end

    # Get the arguments that are defined for this namespace URI.
    def get_args(namespace)
      namespace = self.fix_ns(namespace)
      args = {}
      @args.each {|(pair_ns,ns_key),v| args[ns_key] = v if pair_ns == namespace}
      return args
    end
    
    # Set multiple key/value pairs in one call.
    def update_args(namespace, updates)
      namespace = self.fix_ns(namespace)
      updates.each {|k,v| self.set_arg(namespace, k, v)}
    end

    # Set a single argument in this namespace
    def set_arg(namespace, key, value)
      namespace = self.fix_ns(namespace)
      @args[[namespace, key].freeze] = value
      if namespace != BARE_NS
        @namespace.add(namespace)
      end
    end

    # Remove a single argument from this namespace.
    def del_arg(namespace, key)
      namespace = self.fix_ns(namespace)
      @args.delete([namespace,key].freeze)
    end

    def eq?(other)
      return @args == other.args
    end

  end





end
