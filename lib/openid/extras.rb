
class Object

  def instance_variable_hash
    h = {}
    self.instance_variables.each { |k| h[k] = self.instance_variable_get(k) }
    return h
  end

end

class String

  def starts_with?(other)
    other = other.to_str
    head = self[0, other.length]
    head == other
  end

end
