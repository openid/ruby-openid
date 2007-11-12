
require 'test/unit'
require 'openid/fetchers'
require 'openid/yadis/discovery'
require 'openid/consumer/discovery'
require 'openid/yadis/xrires'
require 'openid/yadis/xri'
require 'openid/message'
require 'openid/util'

### Tests for conditions that trigger DiscoveryFailure

module OpenID
  class SimpleMockFetcher
    def initialize(responses)
      @responses = responses.dup
    end

    def fetch(url, body=nil, headers=nil, limit=nil)
      response = @responses.shift
      Util.assert(body.nil?)
      Util.assert(response.final_url == url)
      return response
    end
  end

  class TestDiscoveryFailure < Test::Unit::TestCase
    def initialize(*args)
      super(*args)

      @responses = [
                    [HTTPResponse._from_raw_data(nil, nil, {}, 'http://network.error/')],
                    [HTTPResponse._from_raw_data(404, nil, {}, 'http://not.found/')],
                    [HTTPResponse._from_raw_data(400, nil, {}, 'http://bad.request/')],
                    [HTTPResponse._from_raw_data(500, nil, {}, 'http://server.error/')],
                    [HTTPResponse._from_raw_data(200, nil, {'x-xrds-location' => 'http://xrds.missing/'},
                                                 'http://header.found/'),
                     HTTPResponse._from_raw_data(404, nil, {}, 'http://xrds.missing/')],
                    ]
    end

    def test_discovery_failure

      @responses.each { |response_set|
        @url = response_set[0].final_url
        OpenID.fetcher = SimpleMockFetcher.new(response_set)
      
        expected_status = response_set[-1].code
        begin
          OpenID.discover(@url)
        rescue Yadis::DiscoveryFailure => why
          assert_equal(why.http_response.code, expected_status)
        else
          flunk('Did not raise DiscoveryFailure')
        end

        OpenID.fetcher = nil
      }
    end
  end

  ### Tests for raising/catching exceptions from the fetcher through
  ### the discover function

  class ErrorRaisingFetcher
    # Just raise an exception when fetch is called

    def initialize(thing_to_raise)
      @thing_to_raise = thing_to_raise
    end

    def fetch(url, body=nil, headers=nil, limit=nil)
      raise @thing_to_raise
    end
  end

  class DidFetch < Exception
    # Custom exception just to make sure it's not handled differently
  end

  class TestFetchException < Test::Unit::TestCase
    # Make sure exceptions get passed through discover function from
    # fetcher.

    def initialize(*args)
      super(*args)

      @cases = [
                Exception.new(),
                DidFetch.new(),
                ArgumentError.new(),
                RuntimeError.new(),
               ]
    end

    def test_fetch_exception
      @cases.each { |exc|
        OpenID.fetcher = ErrorRaisingFetcher.new(exc)
        begin
          OpenID.discover('http://doesnt.matter/')
        rescue Object => thing
          assert(thing.is_a?(exc.class), [thing.class, exc.class, thing].inspect)
        end
        OpenID.fetcher = nil
      }
    end
  end

  ### Tests for openid.consumer.discover.discover

  class TestNormalization < Test::Unit::TestCase
    def test_addingProtocol
      f = ErrorRaisingFetcher.new(RuntimeError.new())
      OpenID.fetcher = f

      begin
        OpenID.discover('users.stompy.janrain.com:8000/x')
      rescue Yadis::DiscoveryFailure => why
        flunk("failed to parse url with port correctly: #{why}")
      rescue RuntimeError
      end

      OpenID.fetcher = nil
    end
  end

  class DiscoveryMockFetcher
    def initialize(documents)
      @redirect = nil
      @documents = documents
      @fetchlog = []
    end

    def fetch(url, body=nil, headers=nil, limit=nil)
      @fetchlog << [url, body, headers]
      if @redirect
        final_url = @redirect
      else
        final_url = url
      end

      begin
        ctype, body = @documents.fetch(url)
      rescue IndexError
        status = 404
        ctype = 'text/plain'
        body = ''
      else
        status = 200
      end

      return HTTPResponse._from_raw_data(status, body, {'content-type' => ctype}, final_url)
    end
  end

  class BaseTestDiscovery < Test::Unit::TestCase
    attr_accessor :id_url, :fetcher_class

    def initialize(*args)
      super(*args)
      @id_url = "http://someuser.unittest/"
      @documents = {}
      @fetcher_class = DiscoveryMockFetcher
    end

    def _checkService(s, server_url, claimed_id=nil,
                      local_id=nil, canonical_id=nil,
                      types=nil, used_yadis=false)
      assert_equal(server_url, s.server_url)
      if types == ['2.0 OP']
        assert(!claimed_id)
        assert(!local_id)
        assert(!s.claimed_id)
        assert(!s.local_id)
        assert(!s.get_local_id())
        assert(!s.compatibility_mode())
        assert(s.is_op_identifier())
        assert_equal(s.preferred_namespace(),
                     OPENID_2_0_MESSAGE_NS)
      else
        assert_equal(claimed_id, s.claimed_id)
        assert_equal(local_id, s.get_local_id())
      end

      if used_yadis
        assert(s.used_yadis, "Expected to use Yadis")
      else
        assert(!s.used_yadis,
               "Expected to use old-style discovery")
      end

      openid_types = {
        '1.1' => OPENID_1_1_TYPE,
        '1.0' => OPENID_1_0_TYPE,
        '2.0' => OPENID_2_0_TYPE,
        '2.0 OP' => OPENID_IDP_2_0_TYPE,
      }

      type_uris = types.collect { |t| openid_types[t] }

      assert_equal(type_uris, s.type_uris)
      assert_equal(canonical_id, s.canonicalID)
    end

    def setup
      # @documents = @documents.dup
      @fetcher = @fetcher_class.new(@documents)
      OpenID.fetcher = @fetcher
    end

    def teardown
      OpenID.fetcher = nil
    end

    def test_blank
      # XXX to avoid > 0 test requirement
    end
  end

#   def readDataFile(filename):
#     module_directory = os.path.dirname(os.path.abspath(__file__))
#     filename = os.path.join(
#         module_directory, 'data', 'test_discover', filename)
#     return file(filename).read()

  class TestDiscovery < BaseTestDiscovery
    include TestDataMixin

    def _discover(content_type, data,
                  expected_services, expected_id=nil)
      if expected_id.nil?
        expected_id = @id_url
      end

      @documents[@id_url] = [content_type, data]
      id_url, services = OpenID.discover(@id_url)

      assert_equal(expected_services, services.length)
      assert_equal(expected_id, id_url)
      return services
    end

    def test_404
      assert_raise(Yadis::DiscoveryFailure) {
        OpenID.discover(@id_url + '/404')
      }
    end

    def test_noOpenID
      services = _discover('text/plain',
                           "junk", 0)

      services = _discover(
                           'text/html',
                           read_data_file('test_discover/openid_no_delegate.html', false),
                           1)

      _checkService(
                    services[0],
                    "http://www.myopenid.com/server",
                    @id_url,
                    @id_url,
                    nil,
                    ['1.1'],
                    false)
    end

    def test_html1
      services = _discover('text/html',
                           read_data_file('test_discover/openid.html', false),
                           1)

      _checkService(services[0],
                    "http://www.myopenid.com/server",
                    @id_url,
                    'http://smoker.myopenid.com/',
                    nil,
                    ['1.1'],
                    false)
    end

    def test_html1Fragment
      # Ensure that the Claimed Identifier does not have a fragment if
      # one is supplied in the User Input.
      content_type = 'text/html'
      data = read_data_file('test_discover/openid.html', false)
      expected_services = 1

      @documents[@id_url] = [content_type, data]
      expected_id = @id_url
      @id_url = @id_url + '#fragment'
      id_url, services = OpenID.discover(@id_url)

      assert_equal(expected_services, services.length)
      assert_equal(expected_id, id_url)

      _checkService(services[0],
                    "http://www.myopenid.com/server",
                    expected_id,
                    'http://smoker.myopenid.com/',
                    nil,
                    ['1.1'],
                    false)
    end

    def test_html2
      services = _discover('text/html',
                           read_data_file('test_discover/openid2.html', false),
                           1)

      _checkService(services[0],
                    "http://www.myopenid.com/server",
                    @id_url,
                    'http://smoker.myopenid.com/',
                    nil,
                    ['2.0'],
                    false)
    end

    def test_html1And2
      services = _discover(
                           'text/html',
                           read_data_file('test_discover/openid_1_and_2.html', false),
                           2)

      services.zip(['2.0', '1.1']).each { |s, t|
          _checkService(s,
                        "http://www.myopenid.com/server",
                        @id_url,
                        'http://smoker.myopenid.com/',
                        nil,
                        [t],
                        false)
      }
    end

    def test_yadisEmpty
      services = _discover('application/xrds+xml',
                           read_data_file('test_discover/yadis_0entries.xml', false),
                           0)
    end

    def test_htmlEmptyYadis
      # HTML document has discovery information, but points to an
      # empty Yadis document.  The XRDS document pointed to by
      # "openid_and_yadis.html"
      @documents[@id_url + 'xrds'] = ['application/xrds+xml',
                                      read_data_file('test_discover/yadis_0entries.xml', false)]

      services = _discover('text/html',
                           read_data_file('test_discover/openid_and_yadis.html', false),
                           1)

      _checkService(services[0],
                    "http://www.myopenid.com/server",
                    @id_url,
                    'http://smoker.myopenid.com/',
                    nil,
                    ['1.1'],
                    false)
    end

    def test_yadis1NoDelegate
      services = _discover('application/xrds+xml',
                           read_data_file('test_discover/yadis_no_delegate.xml', false),
                           1)

      _checkService(services[0],
                    "http://www.myopenid.com/server",
                    @id_url,
                    @id_url,
                    nil,
                    ['1.0'],
                    true)
    end

    def test_yadis2NoLocalID
      services = _discover('application/xrds+xml',
                           read_data_file('test_discover/openid2_xrds_no_local_id.xml', false),
                           1)

      _checkService(services[0],
                    "http://www.myopenid.com/server",
                    @id_url,
                    @id_url,
                    nil,
                    ['2.0'],
                    true)
    end

    def test_yadis2
      services = _discover('application/xrds+xml',
                           read_data_file('test_discover/openid2_xrds.xml', false),
                           1)

      _checkService(services[0],
                    "http://www.myopenid.com/server",
                    @id_url,
                    'http://smoker.myopenid.com/',
                    nil,
                    ['2.0'],
                    true)
    end

    def test_yadis2OP
      services = _discover('application/xrds+xml',
                           read_data_file('test_discover/yadis_idp.xml', false),
                           1)

      _checkService(services[0],
                    "http://www.myopenid.com/server",
                    nil, nil, nil,
                    ['2.0 OP'],
                    true)
    end

    def test_yadis2OPDelegate
      # The delegate tag isn't meaningful for OP entries.
      services = _discover('application/xrds+xml',
                           read_data_file('test_discover/yadis_idp_delegate.xml', false),
                           1)

      _checkService(services[0],
                    "http://www.myopenid.com/server",
                    nil, nil, nil,
                    ['2.0 OP'],
                    true)
    end

    def test_yadis2BadLocalID
      assert_raise(Yadis::DiscoveryFailure) {
        _discover('application/xrds+xml',
                  read_data_file('test_discover/yadis_2_bad_local_id.xml', false),
                  1)
      }
    end

    def test_yadis1And2
      services = _discover('application/xrds+xml',
                           read_data_file('test_discover/openid_1_and_2_xrds.xml', false),
                           1)

      _checkService(services[0],
                    "http://www.myopenid.com/server",
                    @id_url,
                    'http://smoker.myopenid.com/',
                    nil,
                    ['2.0', '1.1'],
                    true)
    end

    def test_yadis1And2BadLocalID
      assert_raise(Yadis::DiscoveryFailure) {
        _discover('application/xrds+xml',
                  read_data_file('test_discover/openid_1_and_2_xrds_bad_delegate.xml', false),
                  1)
      }
    end
  end

  class MockFetcherForXRIProxy

    def initialize(documents, proxy_url=Yadis::XRI::ProxyResolver::DEFAULT_PROXY)
      @documents = documents
      @fetchlog = []
      @proxy_url = nil
    end

    def fetch(url, body=nil, headers=nil, limit=nil)
      @fetchlog << [url, body, headers]

      u = URI::parse(url)
      proxy_host = u.host
      xri = u.path
      query = u.query

      if !headers and !query
        raise ArgumentError.new("No headers or query; you probably didn't " +
                                "mean to do that.")
      end

      if xri.starts_with?('/')
        xri = xri[1..-1]
      end

      begin
        ctype, body = @documents.fetch(xri)
      rescue IndexError
        status = 404
        ctype = 'text/plain'
        body = ''
      else
        status = 200
      end

      return HTTPResponse._from_raw_data(status, body,
                                         {'content-type' => ctype}, url)
    end
  end
end

=begin

  class TestXRIDiscovery < BaseTestDiscovery

    include TestDataMixin

    def initialize(*args)
      super(*args)

      @fetcher_class = MockFetcherForXRIProxy

      @documents = {'=smoker' => ['application/xrds+xml',
                                  read_data_file('test_discover/yadis_2entries_delegate.xml', false)],
        '=smoker*bad' => ['application/xrds+xml',
                          read_data_file('test_discover/yadis_another_delegate.xml', false)]}
    end

    def test_xri
      user_xri, services = OpenID.discover_xri('=smoker')

      _checkService(services[0],
                    "http://www.myopenid.com/server",
                    Yadis::XRI.make_xri("=!1000"),
                    'http://smoker.myopenid.com/',
                    Yadis::XRI.make_xri("=!1000"),
                    ['1.0'],
                    true)

      _checkService(services[1],
                    "http://www.livejournal.com/openid/server.bml",
                    Yadis::XRI.make_xri("=!1000"),
                    'http://frank.livejournal.com/',
                    Yadis::XRI.make_xri("=!1000"),
                    ['1.0'],
                    true)
    end

    def test_xriNoCanonicalID(self):
        user_xri, services = discover.discoverXRI('=smoker*bad')
        assert(!services)

    def test_useCanonicalID(self):
        """When there is no delegate, the CanonicalID should be used with XRI.
        """
        endpoint = discover.OpenIDServiceEndpoint()
        endpoint.claimed_id = XRI("=!1000")
        endpoint.canonicalID = XRI("=!1000")
        assert_equal(endpoint.getLocalID(), XRI("=!1000"))


class TestXRIDiscoveryIDP(BaseTestDiscovery):
    fetcherClass = MockFetcherForXRIProxy

    documents = {'=smoker': ('application/xrds+xml',
                             readDataFile('yadis_2entries_idp.xml')) }

    def test_xri(self):
        user_xri, services = discover.discoverXRI('=smoker')
        assert(services, "Expected services, got zero")
        assert_equal(services[0].server_url,
                             "http://www.livejournal.com/openid/server.bml")


class TestPreferredNamespace(datadriven.DataDrivenTestCase):
    def __init__(self, expected_ns, type_uris):
        datadriven.DataDrivenTestCase.__init__(
            self, 'Expecting %s from %s' % (expected_ns, type_uris))
        self.expected_ns = expected_ns
        self.type_uris = type_uris

    def runOneTest(self):
        endpoint = discover.OpenIDServiceEndpoint()
        endpoint.type_uris = self.type_uris
        actual_ns = endpoint.preferredNamespace()
        assert_equal(actual_ns, self.expected_ns)

    cases = [
        (message.OPENID1_NS, []),
        (message.OPENID1_NS, ['http://jyte.com/']),
        (message.OPENID1_NS, [discover.OPENID_1_0_TYPE]),
        (message.OPENID1_NS, [discover.OPENID_1_1_TYPE]),
        (message.OPENID2_NS, [discover.OPENID_2_0_TYPE]),
        (message.OPENID2_NS, [discover.OPENID_IDP_2_0_TYPE]),
        (message.OPENID2_NS, [discover.OPENID_2_0_TYPE,
                              discover.OPENID_1_0_TYPE]),
        (message.OPENID2_NS, [discover.OPENID_1_0_TYPE,
                              discover.OPENID_2_0_TYPE]),
        ]

class TestIsOPIdentifier(unittest.TestCase):
    def setUp(self):
        self.endpoint = discover.OpenIDServiceEndpoint()

    def test_none(self):
        assert(!self.endpoint.isOPIdentifier())

    def test_openid1_0(self):
        self.endpoint.type_uris = [discover.OPENID_1_0_TYPE]
        assert(!self.endpoint.isOPIdentifier())

    def test_openid1_1(self):
        self.endpoint.type_uris = [discover.OPENID_1_1_TYPE]
        assert(!self.endpoint.isOPIdentifier())

    def test_openid2(self):
        self.endpoint.type_uris = [discover.OPENID_2_0_TYPE]
        assert(!self.endpoint.isOPIdentifier())

    def test_openid2OP(self):
        self.endpoint.type_uris = [discover.OPENID_IDP_2_0_TYPE]
        assert(self.endpoint.isOPIdentifier())

    def test_multipleMissing(self):
        self.endpoint.type_uris = [discover.OPENID_2_0_TYPE,
                                   discover.OPENID_1_0_TYPE]
        assert(!self.endpoint.isOPIdentifier())

    def test_multiplePresent(self):
        self.endpoint.type_uris = [discover.OPENID_2_0_TYPE,
                                   discover.OPENID_1_0_TYPE,
                                   discover.OPENID_IDP_2_0_TYPE]
        assert(self.endpoint.isOPIdentifier())

class TestFromOPEndpointURL(unittest.TestCase):
    def setUp(self):
        self.op_endpoint_url = 'http://example.com/op/endpoint'
        self.endpoint = discover.OpenIDServiceEndpoint.fromOPEndpointURL(
            self.op_endpoint_url)

    def test_isOPEndpoint(self):
        assert(self.endpoint.isOPIdentifier())

    def test_noIdentifiers(self):
        assert_equal(self.endpoint.getLocalID(), nil)
        assert_equal(self.endpoint.claimed_id, nil)

    def test_compatibility(self):
        assert(!self.endpoint.compatibilityMode())

    def test_canonicalID(self):
        assert_equal(self.endpoint.canonicalID, nil)

    def test_serverURL(self):
        assert_equal(self.endpoint.server_url, self.op_endpoint_url)

class TestDiscoverFunction(unittest.TestCase):
    def setUp(self):
        self._old_discoverURI = discover.discoverURI
        self._old_discoverXRI = discover.discoverXRI

        discover.discoverXRI = self.discoverXRI
        discover.discoverURI = self.discoverURI

    def tearDown(self):
        discover.discoverURI = self._old_discoverURI
        discover.discoverXRI = self._old_discoverXRI

    def discoverXRI(self, identifier):
        return 'XRI'

    def discoverURI(self, identifier):
        return 'URI'

    def test_uri(self):
        assert_equal('URI', discover.discover('http://woo!'))

    def test_uriForBogus(self):
        assert_equal('URI', discover.discover('not a URL or XRI'))

    def test_xri(self):
        assert_equal('XRI', discover.discover('xri://=something'))

    def test_xriChar(self):
        assert_equal('XRI', discover.discover('=something'))

class TestEndpointSupportsType(unittest.TestCase):
    def setUp(self):
        self.endpoint = discover.OpenIDServiceEndpoint()

    def failUnlessSupportsOnly(self, *types):
        for t in [
            'foo',
            discover.OPENID_1_1_TYPE,
            discover.OPENID_1_0_TYPE,
            discover.OPENID_2_0_TYPE,
            discover.OPENID_IDP_2_0_TYPE,
            ]:
            if t in types:
                assert(self.endpoint.supportsType(t),
                                "Must support %r" % (t,))
            else:
                assert(!self.endpoint.supportsType(t),
                            "Shouldn't support %r" % (t,))

    def test_supportsNothing(self):
        self.failUnlessSupportsOnly()

    def test_openid2(self):
        self.endpoint.type_uris = [discover.OPENID_2_0_TYPE]
        self.failUnlessSupportsOnly(discover.OPENID_2_0_TYPE)

    def test_openid2provider(self):
        self.endpoint.type_uris = [discover.OPENID_IDP_2_0_TYPE]
        self.failUnlessSupportsOnly(discover.OPENID_IDP_2_0_TYPE,
                                    discover.OPENID_2_0_TYPE)

    def test_openid1_0(self):
        self.endpoint.type_uris = [discover.OPENID_1_0_TYPE]
        self.failUnlessSupportsOnly(discover.OPENID_1_0_TYPE)

    def test_openid1_1(self):
        self.endpoint.type_uris = [discover.OPENID_1_1_TYPE]
        self.failUnlessSupportsOnly(discover.OPENID_1_1_TYPE)

    def test_multiple(self):
        self.endpoint.type_uris = [discover.OPENID_1_1_TYPE,
                                   discover.OPENID_2_0_TYPE]
        self.failUnlessSupportsOnly(discover.OPENID_1_1_TYPE,
                                    discover.OPENID_2_0_TYPE)

    def test_multipleWithProvider(self):
        self.endpoint.type_uris = [discover.OPENID_1_1_TYPE,
                                   discover.OPENID_2_0_TYPE,
                                   discover.OPENID_IDP_2_0_TYPE]
        self.failUnlessSupportsOnly(discover.OPENID_1_1_TYPE,
                                    discover.OPENID_2_0_TYPE,
                                    discover.OPENID_IDP_2_0_TYPE,
                                    )

def pyUnitTests():
    return datadriven.loadTests(__name__)

if __name__ == '__main__':
    suite = pyUnitTests()
    runner = unittest.TextTestRunner()
    runner.run(suite)

=end
