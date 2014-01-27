module OpenID
  class Serializer
    SERIALIZABLE = {
      "OpenID::OpenIDServiceEndpoint" => [OpenID::OpenIDServiceEndpoint, 0],
      "OpenID::Consumer::DiscoveredServices" => [OpenID::Consumer::DiscoveredServices, 3]
    }

    def self.serialize(instance)
      klass = instance.class.name
      raise "unable to serialize #{klass}" unless SERIALIZABLE[klass]
      [klass, instance.instance_variables.map { |v| [v.to_s, instance.instance_variable_get(v)] }]
    end

    def self.deserialize(klass, data)
      klass, arguments = SERIALIZABLE[klass] || raise("unable to deserialize #{klass}")
      instance = klass.new(*Array.new(arguments))
      data.each { |k,v| instance.instance_variable_set(k,v) }
      instance
    end
  end
end
