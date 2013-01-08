class String
  def starts_with?(other)
    other = other.to_s
    head = self[0, other.length]
    head == other
  end

  def ends_with?(other)
    other = other.to_s
    tail = self[-1 * other.length, other.length]
    tail == other
  end
end
