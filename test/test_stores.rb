require 'test/unit'
require 'openid/store/interface'
require 'openid/association'

class OpenIDStoreTestCase < Test::Unit::TestCase

  def test_abstract_class
    # the abstract made concrete
    abc = OpenID::Store.new()
    server_url = "http://server.com/"
    association = OpenID::Association.new("foo", "bar", Time.now, Time.now + 10, "dummy")
    
    assert_raise(NotImplementedError) { 
      abc.store_association(server_url, association)
    }

    assert_raise(NotImplementedError) { 
      abc.get_association(server_url)
    }

    assert_raise(NotImplementedError) { 
      abc.remove_association(server_url, association.handle)
    }

    assert_raise(NotImplementedError) { 
      abc.use_nonce(server_url, Time.now.to_i, "foo")
    }

    assert_raise(NotImplementedError) { 
      abc.cleanup_nonces()
    }

    assert_raise(NotImplementedError) { 
      abc.cleanup_associations()
    }

    assert_raise(NotImplementedError) { 
      abc.cleanup()
    }
    
  end


end
