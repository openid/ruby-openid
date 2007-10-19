
module OpenID

  class AssertionError < Exception
  end

  def assert(value, message=nil)
    if not value
      raise AssertionError, message or value
    end
  end

end
