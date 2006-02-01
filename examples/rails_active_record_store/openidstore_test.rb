require File.dirname(__FILE__) + '/../test_helper'

# ugly way to get at StoreTestCase module
require File.dirname(__FILE__) + '/../../vendor/openid/test/storetestcase'

class OpenidTest < Test::Unit::TestCase

  include OpenidHelper
  include StoreTestCase

  def setup
    @store = self
  end
  
end
