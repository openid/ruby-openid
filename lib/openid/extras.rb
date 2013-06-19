class String
  def starts_with?(other)
    other = other.to_s
    head = self[0, other.length]
    head == other
  end unless ''.respond_to?(:starts_with?)

  def ends_with?(other)
    other = other.to_s
    tail = self[-1 * other.length, other.length]
    tail == other
  end unless ''.respond_to?(:ends_with?)
end
