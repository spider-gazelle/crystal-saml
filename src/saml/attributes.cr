module SAML
  # SAML2 Attributes from the AttributeStatement
  class Attributes
    include Enumerable({String, Array(String?)})

    @attributes : Hash(String, Array(String?))

    # By default, [] returns only the first value for backwards compatibility
    # Set to false to return all values
    @@single_value_compatibility = true

    def self.single_value_compatibility : Bool
      @@single_value_compatibility
    end

    def self.single_value_compatibility=(value : Bool)
      @@single_value_compatibility = value
    end

    def initialize(attrs = {} of String => Array(String?))
      @attributes = {} of String => Array(String?)
      attrs.each do |key, values|
        @attributes[key] = values.map(&.as(String?))
      end
    end

    # Iterate over all attributes
    def each(&)
      @attributes.each do |name, values|
        yield({name, values})
      end
    end

    # Test attribute presence by name
    def includes?(name : String | Symbol) : Bool
      @attributes.has_key?(canonize_name(name))
    end

    # Return first value for an attribute
    def single(name : String | Symbol) : String?
      key = canonize_name(name)
      @attributes[key]?.try(&.first) if includes?(key)
    end

    # Return all values for an attribute
    def multi(name : String | Symbol) : Array(String?)?
      @attributes[canonize_name(name)]?
    end

    # Retrieve attribute value(s)
    # Returns first value if single_value_compatibility = true
    # Returns all values if single_value_compatibility = false
    def [](name : String | Symbol) : String? | Array(String?)?
      self.class.single_value_compatibility ? single(name) : multi(name)
    end

    # Return all attributes as a hash
    def all : Hash(String, Array(String?))
      @attributes
    end

    # Set attribute values
    def []=(name : String | Symbol, values)
      set(name, values)
    end

    def set(name : String | Symbol, values)
      normalized = values.is_a?(Array) ? values.map(&.as(String?)) : [values.as(String?)]
      @attributes[canonize_name(name)] = normalized
    end

    # Add values to an attribute
    def add(name : String | Symbol, values = [] of String?)
      key = canonize_name(name)
      @attributes[key] ||= [] of String?
      normalized = values.is_a?(Array) ? values.map(&.as(String?)) : [values.as(String?)]
      @attributes[key] += normalized
    end

    # Compare to another Attributes collection
    def ==(other : Attributes) : Bool
      all == other.all
    end

    # Fetch attribute value using name or regex
    def fetch(name : String | Symbol | Regex) : String? | Array(String?)?
      if name.is_a?(Regex)
        @attributes.each_key do |key|
          return self[key] if name.matches?(key)
        end
      else
        canon_name = canonize_name(name)
        @attributes.each_key do |key|
          return self[key] if canon_name == canonize_name(key)
        end
      end
      nil
    end

    # Stringify names for consistency
    private def canonize_name(name : String | Symbol) : String
      name.to_s
    end
  end
end
