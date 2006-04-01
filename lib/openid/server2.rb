require 'openid/util'
require 'openid/association'
require 'openid/dh'
require 'openid/trustroot'

module OpenID

  module Server
    
    class OpenIDRequest
      
      attr_reader :mode

      def initialize(mode)
        @mode = mode
      end

    end

    class CheckAuthRequest < OpenIDRequest
      
      attr_accessor :assoc_handle, :sig, :signed, :invalidate_handle

      def initialize(assoc_handle, sig, signed, invalidate_handle=nil)
        super('check_authentication')
        @assoc_handle = assoc_handle
        @sig = sig
        @signed = signed
        @invalidate_handle = invalidate_handle
      end

      def CheckAuthRequest.from_query(query)       
        assoc_handle = query['openid.assoc_handle']
        sig = query['openid.sig']
        signed = query['openid.signed']

        unless assoc_handle and sig and signed
          raise ProtocolError, "#{@mode} request missing required paramter"
        end

        signed = signed.split(',')
        signed_pairs = []

        signed.each do |field|
          if field == 'mode'
            value = 'id_res'
          else
            value = query['openid.'+field]
            if value.nil?
              raise ProtocolError, "Couldn't find signed field #{field}"
            end
          end
          signed_pairs << [field, value]
        end
        
        return new(assoc_handle, sig, signed_pairs)
      end

      def answer(signatory)
        is_valid = signatory.verify(@assoc_handle, @sig, @signed)
        signatory.invalidate(assoc_handle, true)

        response = OpenIDResponse.new(self)
        response.fields['is_valid'] = is_valid ? 'true' : 'false'
        
        if @invalidate_handle
          assoc = signatory.get_association(@invalidate_handle, false)
          unless assoc
            response.fields['invalidate_handle'] = @invalidate_handle
          end          
        end

        return response
      end

    end
    
    class AssociateRequest < OpenIDRequest

      attr_accessor :session_type, :assoc_type, :pubkey

      def initialize
        super('associate')
        @session_type = 'plaintext'
        @assoc_type = 'HMAC-SHA1'
        @pubkey = nil
      end

      def AssociateRequest.from_query(query)
        req = new
        session_type = query['openid.session_type']
        if session_type
          req.session_type = session_type
          if session_type == 'DH-SHA1'
            pubkey = query['openid.dh_consumer_public']
            if pubkey
              req.pubkey = OpenID::Util.base64_to_num(pubkey)
            else
              raise ProtocolError, 'No public key found for DH-SHA1 session'
            end

            # XXX: add mod and gen... coming soon
          end
        end
        return req
      end

      def answer(assoc)
        response = OpenIDResponse.new(self)

        fields = {
          'expires_in' => assoc.expires_in.to_s,
          'assoc_type' => 'HMAC-SHA1',
          'assoc_handle' => assoc.handle
        }

        response.fields.update(fields)
        
        if @session_type == 'DH-SHA1'
          # XXX: get dh mod and gen
          dh = OpenID::DiffieHellman.new
          mac_key = dh.xor_secrect(@pubkey, assoc.secret)
          
          dh_fields = {
            'session_type' => @session_type,
            'dh_server_public' => OpenID::Util.num_to_base64(dh.public),
            'enc_mac_key' => OpenID::Util.to_base64(mac_key)
          }
          response.fields.update(dh_fields)
          
        elsif @session_type == 'plaintext'
          response.fields['mac_key'] = OpenID::Util.to_base64(assoc.secret)

        else
          raise ProtocolError, "Don't know about session type #{@session_type}"
        end

        return response
      end
      
    end

    class CheckIDRequest < OpenIDRequest
      
      attr_accessor :identity, :return_to, :trust_root, :immediate, :assoc_handle

      def initialize(mode, identity, return_to, trust_root=nil)
        unless ['checkid_immediate', 'checkid_setup'].include?(mode)
          raise ProtocolError, "Can't create CheckIDRequest for mode #{mode}"
        end

        super(mode)
        @identity = identity
        @return_to = return_to
        @trust_root = trust_root
        @immediate = mode == 'checkid_immediate' ? true : false
        @assoc_handle = nil
      end
       
      def CheckIDRequest.from_query(query)
        mode = query['openid.mode']

        identity = query['openid.identity']
        raise ProtocolError, 'openid.identity missing' unless identity

        return_to = query['openid.return_to']
        raise ProtocolError, 'openid.return_to missing' unless return_to

        unless OpenID::TrustRoot.parse(return_to)
          raise MalformedReturnURL(return_to)
        end

        trust_root = query['openid.trust_root']
       
        req = new(mode, identity, return_to, trust_root)
        req.assoc_handle = query['openid.assoc_handle']
        return req
      end

      def trust_root_valid
        return true unless @trust_root
        tr = OpenID::TrustRoot.parse(@trust_root)
        raise MalformedTrustRoot.new(@trust_root) if tr.nil?
        return tr.validate_url(@return_to)
      end

      def answer(allow, setup_url=nil)
        if allow or @immediate
          mode = 'id_res'
        else
          mode = 'cancel'
        end
        
        response = CheckIDResponse.new(self, mode)
        
        if allow
          unless self.trust_root_valid
            raise UntrustedReturnURL.new(@return_to, @trust_root)
          end
          response.fields['openid.identity'] = @identity
          response.fields['openid.return_to'] = @return_to
        else
          response.signed.clear
          if @immediate
            unless setup_url
              raise ArgumentError, "setup_url is required for allow=false in immediate mode"
            end
            response.fields['openid.user_setup_url'] = setup_url
          end

        end
        
        return response
      end

      def cancel_url
        if @immediate
          raise ProtocolError, 'cancel is not an appropriate reponse to immediate mode requests'
        end
        return OpenID::Util.append_args(@return_to,{'openid.mode' => 'cancel'})
      end

      def identity_url
        @identity
      end

    end


    class OpenIDResponse

      attr_accessor :request, :fields

      def initialize(request)
        @request = request
        @fields = {}
      end

    end

    class CheckIDResponse < OpenIDResponse
      
      attr_accessor :signed

      def initialize(request, mode='id_res')
        super(request)
        @fields['openid.mode'] = mode
        @signed = []
        if mode == 'id_res'
          @signed += ['mode', 'identity', 'return_to']
        end
      end

    end

    class Signatory
      @@secret_lifetime = 14 * 24 * 60 * 6
      @@normal_key = 'http://localhost/|normal'
      @@dumb_key = 'http://localhost/|dumb'
      
      def initialize(store)
        @store = store
      end

      def verify(assoc_handle, sig, signed_pairs, dumb=true)
        assoc = self.get_association(assoc_handle, dumb)
        unless assoc
          OpenID::Util.log("failed to get assoc with handle #{assoc_handle} to verify sig #{sig}")
          return false
        end
        
        expected_sig = OpenID::Util.to_base64(assoc.sign(signed_pairs))

        if sig == expected_sig
          return true
        else
          OpenID::Util.log("signture mismatch: expected #{expected_sig}, got #{sig}")
          return false
        end
      end

      def sign(response)
        # get a deep copy of the response
        signed_response = Marshal.load(Marshal.dump(response))
        assoc_handle = response.request.assoc_handle

        if assoc_handle
          assoc = self.get_association(assoc_handle, false)
          unless assoc
            # no assoc for handle, fall back to dumb mode
            signed_response.fields['openid.invalidate_handle'] = assoc_handle
            assoc = self.create_association(true)
          end
        else
          # dumb mode
          assoc = self.create_association(true)
        end
        
        signed_response.fields['openid.assoc_handle'] = assoc.handle
        assoc.add_signature(signed_response.signed,
                            signed_response.fields)
        return signed_response
      end

      def create_association(dumb=true, assoc_type='HMAC-SHA1')
        secret = OpenID::Util.get_random_bytes(20)
        uniq = OpenID::Util.to_base64(OpenID::Util.get_random_bytes(4))
        handle = "{%s}{%x}{%s}" % [assoc_type, Time.now.to_i, uniq]
        assoc = Association.from_expires_in(@@secret_lifetime,
                                            handle,
                                            secret,
                                            assoc_type)

        key = dumb ? @@dumb_key : @@normal_key
        @store.store_association(key, assoc)
        return assoc
      end

      def get_association(assoc_handle, dumb)
        if assoc_handle.nil?
          raise ArgumentError, 'assoc_handle must not be nil'
        end
        
        key = dumb ? @@dumb_key : @@normal_key
        
        assoc = @store.get_association(key, assoc_handle)
        if assoc and assoc.expired?
          @store.remove_association(key, assoc_handle)
          assoc = nil
        end
        
        return assoc
      end

      def invalidate(assoc_handle, dumb)
        key = dumb ? @@dumb_key : @@normal_key
        @store.remove_association(key, assoc_handle)
      end

    end

    HTTP_REDIRECT = 302
    HTTP_OK = 200

    class WebResponse
      
      attr_accessor :code, :headers, :body

      def initialize
        @code = HTTP_OK
        @headers = {}
        @body = ''
      end

      def set_redirect(url)
        @code = HTTP_REDIRECT
        @headers['location'] = url
      end

      def is_redirect?
        @code == HTTP_REDIRECT
      end

      def redirect_url
        @headers['location']
      end

    end

    class Encoder
      
      def encode(response)
        request = response.request
        wr = WebResponse.new
        if ['checkid_setup', 'checkid_immediate'].include?(request.mode)
          location = OpenID::Util.append_args(request.return_to,
                                              response.fields)          
          wr.set_redirect(location)
        else
          wr.body = OpenID::Util.kvform(response.fields)          
        end
        return wr
      end

    end

    class SigningEncoder < Encoder
      
      def initialize(signatory)
        if signatory.nil?
          raise ArgumentError, "signatory must not be nil"
        end
        @signatory = signatory
      end

      def encode(response)
        request = response.request
        if ['checkid_setup', 'checkid_immediate'].include?(request.mode)
          if response.signed.length > 0
            if response.fields.has_key?('openid.sig')
              raise ArgumentError, 'response already signed'
            end
            response = @signatory.sign(response)            
          end          
        end
        return super(response)
      end

    end

    class Decoder

      def decode(query)
        return nil if query.length == 0
        
        mode = query['openid.mode']
        return nil if mode.nil?

        case mode
        when 'checkid_setup', 'checkid_immediate'
          return CheckIDRequest.from_query(query)

        when 'check_authentication'
          return CheckAuthRequest.from_query(query)

        when 'associate'
          return AssociateRequest.from_query(query)
          
        else
          raise nil
        end
        
      end

    end


    class OpenIDServer
      
      def initialize(store)
        @store = store
        @signatory = Signatory.new(store)
        @encoder = SigningEncoder.new(@signatory)
        @decoder = Decoder.new
      end

      def handle_request(request)
        return self.send('openid_'+request.mode, request)
      end
      
      def encode_response(response)
        return @encoder.encode(response)
      end
      
      def decode_request(query)
        return @decoder.decode(query)
      end

      def openid_check_authentication(request)
        return request.answer(@signatory)
      end

      def openid_associate(request)
        assoc = @signatory.create_association(false)
        return request.answer(assoc)
      end

    end

    class ProtocolError < Exception; end
    class EncodingError < Exception; end    
    class MalformedReturnURL < ProtocolError; end
    class MalformedTrustRoot < ProtocolError; end

    class UntrustedReturnURL < ProtocolError
      attr_reader :return_to, :trust_root
      def initialize(return_to, trust_root)
        @return_to = return_to
        @trust_root = trust_root        
      end
    end

  end

end
