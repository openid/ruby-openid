require 'test/unit'
require 'fileutils'

require 'openid/util'
require 'openid/filestore'


$allowed_handle = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~'
$allowed_nonce = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

def generateHandle(n)
  OpenID::Util.random_string(n, $allowed_handle)
end

def generateNonce
  OpenID::Util.random_string(8, $allowed_nonce)
end

def generateSecret(n, chars=nil)
  OpenID::Util.random_string(n, chars)
end
  
module StoreTestCase 

  def test_store
    server_url = "http://www.myopenid.com/openid"
    secret = generateSecret(20)
    handle = generateHandle(128)
    assoc = OpenID::ConsumerAssociation.from_expires_in(600, server_url, handle, secret)

    # Make sure that a missing association returns no result
    missing_assoc = @store.get_association(server_url)
    assert(missing_assoc.nil?)

    # Check that after storage, getting returns the same result
    @store.store_association(assoc)
    retrieved_assoc = @store.get_association(server_url)
    assert(retrieved_assoc.secret == assoc.secret)
    assert(retrieved_assoc.handle == assoc.handle)
    assert(retrieved_assoc.server_url == assoc.server_url)
    assert(retrieved_assoc == assoc)

    # more than once
    retrieved_assoc = @store.get_association(server_url)
    assert(retrieved_assoc.secret == assoc.secret)
    assert(retrieved_assoc.handle == assoc.handle)
    assert(retrieved_assoc.server_url == assoc.server_url)

    # storing more than once has no ill effect
    @store.store_association(assoc)
    retrieved_assoc = @store.get_association(server_url)
    assert(retrieved_assoc.secret == assoc.secret)
    assert(retrieved_assoc.handle == assoc.handle)
    assert(retrieved_assoc.server_url == assoc.server_url)
    assert(retrieved_assoc == assoc)

    # removing an assoc that does not exist returns not present
    present = @store.removeAssociation(server_url+'x', handle)
    assert(present == false)

    # removing an assoc that is present returns present
    present = @store.removeAssociation(server_url, handle)
    assert(present)

    # but not present on subsequent calls
    present = @store.removeAssociation(server_url, handle)
    assert(present == false)

    # one association w/ server_url
    @store.store_association(assoc)
    handle2 = generateHandle(128)
    assoc2 = OpenID::ConsumerAssociation.from_expires_in(600, server_url,
                                               handle2, secret)
    @store.store_association(assoc2)
    
    # After storing an association with a different handle, but the
    # same server_url, the most recent association is available. There
    # is no guarantee either way about the first association. (and
    # thus about the return value of removeAssociation)
    retrieved_assoc = @store.get_association(server_url)
    assert retrieved_assoc.server_url == server_url
    assert retrieved_assoc.handle == handle2
    assert retrieved_assoc.secret == secret

    ### Nonce stuff
    nonce1 = generateNonce
    
    # a nonce is present by default
    present = @store.use_nonce(nonce1)
    assert present == false

    # Storing once causes use_nonce to return True the first, and only
    # the first, time it is called after the store.
    @store.store_nonce(nonce1)
    present = @store.use_nonce(nonce1)
    assert present
    present = @store.use_nonce(nonce1)
    assert present == false
    
    # Storing twice has the same effect as storing once.
    @store.store_nonce(nonce1)
    @store.store_nonce(nonce1)
    present = @store.use_nonce(nonce1)
    assert present
    present = @store.use_nonce(nonce1)
    assert present == false
    
    ### Auth key stuff
    
    # there is no key to start with, so generate a new key and return it
    key = @store.get_auth_key
    
    # the second time we should return the same key as before
    key2 = @store.get_auth_key
    assert key == key2

  end

end


class FileStoreTestCase < Test::Unit::TestCase
  include StoreTestCase

  @@dir = "/tmp/filstoretest"

  def setup
    FileUtils.rm_rf(@@dir)
    @store = OpenID::FilesystemOpenIDStore.new(@@dir)    
  end

  def teardown
    FileUtils.rm_rf(@@dir)
  end
end

