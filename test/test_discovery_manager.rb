
require 'test/unit'
require 'openid/consumer/discovery_manager'

require 'testutil'

module OpenID
  class TestDiscoveredServices < Test::Unit::TestCase
    def setup
      @starting_url = "http://starting.url.com/"
      @yadis_url = "http://starting.url.com/xrds"
      @services = ["bogus", "not_a_service"]

      @disco_services = Consumer::DiscoveredServices.new(@starting_url,
                                                         @yadis_url,
                                                         @services.dup)
    end

    def test_next
      assert_equal(@disco_services.next, @services[0])
      assert_equal(@disco_services.current, @services[0])

      assert_equal(@disco_services.next, @services[1])
      assert_equal(@disco_services.current, @services[1])

      assert_equal(@disco_services.next, nil)
      assert_equal(@disco_services.current, nil)
    end

    def test_for_url
      assert(@disco_services.for_url?(@starting_url))
      assert(@disco_services.for_url?(@yadis_url))

      assert(!@disco_services.for_url?(nil))
      assert(!@disco_services.for_url?("invalid"))
    end

    def test_started
      assert(!@disco_services.started?)
      @disco_services.next
      assert(@disco_services.started?)
      @disco_services.next
      assert(@disco_services.started?) 
      @disco_services.next
      assert(!@disco_services.started?)
    end

    def test_empty
      assert(Consumer::DiscoveredServices.new(nil, nil, []).empty?)

      assert(!@disco_services.empty?)

      @disco_services.next
      @disco_services.next

      assert(@disco_services.started?)
    end
  end

  # I need to be able to test the protected methods; this lets me do
  # that.
  class PassthroughDiscoveryManager < Consumer::SessionDiscoveryManager
    def method_missing(m, *args)
      method(m).call(*args)
    end
  end

  class TestSessionDiscoveryManager < Test::Unit::TestCase
    def setup
      @session = {}
      @url = "http://unittest.com/"
      @key_suffix = "testing"
      @yadis_url = "http://unittest.com/xrds"
      @manager = PassthroughDiscoveryManager.new(@session, @url, @key_suffix)
      @key = @manager.session_key
    end

    def test_construct
      # Make sure the default session key suffix is not nil.
      m = Consumer::SessionDiscoveryManager.new(nil, nil)
      assert(!m.instance_variable_get("@session_key_suffix").nil?)

      m = Consumer::SessionDiscoveryManager.new(nil, nil, "override")
      assert_equal(m.instance_variable_get("@session_key_suffix"), "override")
    end

    def test_get_next_service
      assert_equal(@session[@key], nil)

      next_service = @manager.get_next_service {
        [@yadis_url, ["one", "two", "three"]]
      }

      disco = @session[@key]
      assert_equal(disco.current, "one")
      assert_equal(next_service, "one")
      assert(disco.for_url?(@url))
      assert(disco.for_url?(@yadis_url))

      # The first two calls to get_next_service should return the
      # services in @disco.
      assert_equal(@manager.get_next_service, "two")
      assert_equal(@manager.get_next_service, "three")
      assert_equal(@session[@key], disco)

      # The manager is exhausted and should be deleted and a new one
      # should be created.
      @manager.get_next_service {
        [@yadis_url, ["four"]]
      }

      disco2 = @session[@key]
      assert_equal(disco2.current, "four")

      # create_manager may return a nil manager, in which case the
      # next service should be nil.
      @manager.extend(OpenID::InstanceDefExtension)
      @manager.instance_def(:create_manager) do |yadis_url, services|
        nil
      end

      result = @manager.get_next_service { |url|
        ["unused", []]
      }

      assert_equal(result, nil)
    end

    def test_cleanup
      # With no preexisting manager, cleanup() returns nil.
      assert_equal(@manager.cleanup, nil)

      # With a manager, it returns the manager's current service.
      disco = Consumer::DiscoveredServices.new(@url, @yadis_url, ["one", "two"])

      @session[@key] = disco
      assert_equal(@manager.cleanup, nil)
      assert_equal(@session[@key], nil)

      @session[@key] = disco
      disco.next
      assert_equal(@manager.cleanup, "one")
      assert_equal(@session[@key], nil)

      # The force parameter should be passed through to get_manager
      # and destroy_manager.
      force_value = "yo"
      testcase = self

      m = Consumer::DiscoveredServices.new(nil, nil, ["inner"])
      m.next

      @manager.extend(OpenID::InstanceDefExtension)
      @manager.instance_def(:get_manager) do |force|
        testcase.assert_equal(force, force_value)
        m
      end

      @manager.instance_def(:destroy_manager) do |force|
        testcase.assert_equal(force, force_value)
      end

      assert_equal("inner", @manager.cleanup(force_value))
    end

    def test_get_manager
      # get_manager should always return the loaded manager when
      # forced.
      @session[@key] = "bogus"
      assert_equal("bogus", @manager.get_manager(true))

      # When not forced, only managers for @url should be returned.
      disco = Consumer::DiscoveredServices.new(@url, @yadis_url, ["one"])
      @session[@key] = disco
      assert_equal(@manager.get_manager, disco)

      # Try to get_manager for a manger that doesn't manage @url:
      disco2 = Consumer::DiscoveredServices.new("http://not.this.url.com/",
                                                "http://other.yadis.url/", ["one"])
      @session[@key] = disco2
      assert_equal(@manager.get_manager, nil)
      assert_equal(@manager.get_manager(true), disco2)
    end

    def test_create_manager
    end

    def test_destroy_manager
    end

    def test_session_key
    end

    def test_store
    end

    def test_load
    end

    def test_destroy
    end
  end
end
