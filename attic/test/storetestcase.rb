require 'openid/util'
require 'openid/association'

module StoreTestCase 
  
  @@allowed_handle = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~'
  @@allowed_nonce = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
  
  def _gen_nonce
    OpenID::Util.random_string(8, @@allowed_nonce)
  end

  def _gen_handle(n)
    OpenID::Util.random_string(n, @@allowed_handle)
  end

  def _gen_secret(n, chars=nil)
    OpenID::Util.random_string(n, chars)
  end

  def _gen_assoc(issued, lifetime=600)
    secret = _gen_secret(20)
    handle = _gen_handle(128)
    OpenID::Association.new(handle, secret, Time.now.to_i + issued, lifetime,
                            'HMAC-SHA1') 
  end
    
  def _check_retrieve(url, handle=nil, expected=nil)
    ret_assoc = @store.get_association(url, handle)

    if expected.nil? or @store.dumb?
      assert_nil(ret_assoc)
    else
      assert_equal(ret_assoc, expected)
      assert_equal(ret_assoc.handle, expected.handle)
      assert_equal(ret_assoc.secret, expected.secret)
    end
  end

  def _check_remove(url, handle, expected)
    present = @store.remove_association(url, handle)
    expected_present = ((not @store.dumb?) and expected)
    assert ((not expected_present and not present) or \
            (expected_present and present))    
  end

  def test_store
    server_url = "http://www.myopenid.com/openid"
    assoc = _gen_assoc(issued=0)

    # Make sure that a missing association returns no result
    _check_retrieve(server_url)

    # Check that after storage, getting returns the same result
    @store.store_association(server_url, assoc)
    _check_retrieve(server_url, nil, assoc)

    # more than once
    _check_retrieve(server_url, nil, assoc)

    # Storing more than once has no ill effect
    @store.store_association(server_url, assoc)
    _check_retrieve(server_url, nil, assoc)

    # Removing an association that does not exist returns not present
    _check_remove(server_url, assoc.handle + 'x', false)

    # Removing an association that does not exist returns not present
    _check_remove(server_url + 'x', assoc.handle, false)

    # Removing an association that is present returns present
    _check_remove(server_url, assoc.handle, true)

    # but not present on subsequent calls
    _check_remove(server_url, assoc.handle, false)

    # Put assoc back in the store
    @store.store_association(server_url, assoc)

    # More recent and expires after assoc
    assoc2 = _gen_assoc(issued=1)
    @store.store_association(server_url, assoc2)

    # After storing an association with a different handle, but the
    # same server_url, the handle with the later expiration is returned.
    _check_retrieve(server_url, nil, assoc2)

    # We can still retrieve the older association
    _check_retrieve(server_url, assoc.handle, assoc)

    # Plus we can retrieve the association with the later expiration
    # explicitly
    _check_retrieve(server_url, assoc2.handle, assoc2)

    # More recent, and expires earlier than assoc2 or assoc. Make sure
    # that we're picking the one with the latest issued date and not
    # taking into account the expiration.
    assoc3 = _gen_assoc(issued=2, lifetime=100)
    @store.store_association(server_url, assoc3)

    _check_retrieve(server_url, nil, assoc3)
    _check_retrieve(server_url, assoc.handle, assoc)
    _check_retrieve(server_url, assoc2.handle, assoc2)
    _check_retrieve(server_url, assoc3.handle, assoc3)

    _check_remove(server_url, assoc2.handle, true)

    _check_retrieve(server_url, nil, assoc3)
    _check_retrieve(server_url, assoc.handle, assoc)
    _check_retrieve(server_url, assoc2.handle, nil)
    _check_retrieve(server_url, assoc3.handle, assoc3)

    _check_remove(server_url, assoc2.handle, false)
    _check_remove(server_url, assoc3.handle, true)

    _check_retrieve(server_url, nil, assoc)
    _check_retrieve(server_url, assoc.handle, assoc)
    _check_retrieve(server_url, assoc2.handle, nil)
    _check_retrieve(server_url, assoc3.handle, nil)

    _check_remove(server_url, assoc2.handle, false)
    _check_remove(server_url, assoc.handle, true)
    _check_remove(server_url, assoc3.handle, false)

    _check_retrieve(server_url, nil, nil)
    _check_retrieve(server_url, assoc.handle, nil)
    _check_retrieve(server_url, assoc2.handle, nil)
    _check_retrieve(server_url, assoc3.handle, nil)

    _check_remove(server_url, assoc2.handle, false)
    _check_remove(server_url, assoc.handle, false)
    _check_remove(server_url, assoc3.handle, false)
  end
    
  def test_nonce
    nonce1 = _gen_nonce
    
    assert_not_nil(nonce1)

    # a nonce is present by default
    present = @store.use_nonce(nonce1)
    assert_equal(present, false)

    # Storing once causes use_nonce to return true the first, and only
    # the first, time it is called after the store.
    @store.store_nonce(nonce1)
    present = @store.use_nonce(nonce1)
    assert present
    present = @store.use_nonce(nonce1)
    assert_equal(present, false)
    
    # Storing twice has the same effect as storing once.
    @store.store_nonce(nonce1)
    @store.store_nonce(nonce1)
    present = @store.use_nonce(nonce1)
    assert present
    present = @store.use_nonce(nonce1)
    assert_equal(present, false)
    
    ### Auth key stuff
    
    # there is no key to start with, so generate a new key and return it
    key = @store.get_auth_key
    
    # the second time we should return the same key as before
    key2 = @store.get_auth_key
    assert key == key2
  end

end


