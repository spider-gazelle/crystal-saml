require "./spec_helper"

describe SAML::Attributes do
  describe "#initialize" do
    it "creates empty attributes" do
      attrs = SAML::Attributes.new
      attrs.all.should be_empty
    end

    it "accepts initial attributes" do
      attrs = SAML::Attributes.new({"name" => ["John"]})
      attrs["name"].should eq "John" # Single value compatibility
    end
  end

  describe "#[]" do
    it "returns first value in single value compatibility mode" do
      attrs = SAML::Attributes.new
      attrs.add("email", ["john@example.com", "jane@example.com"])

      SAML::Attributes.single_value_compatibility = true
      attrs["email"].should eq "john@example.com"
    end

    it "returns all values when single value compatibility is off" do
      attrs = SAML::Attributes.new
      attrs.add("email", ["john@example.com", "jane@example.com"])

      SAML::Attributes.single_value_compatibility = false
      attrs["email"].should eq ["john@example.com", "jane@example.com"]

      # Reset for other tests
      SAML::Attributes.single_value_compatibility = true
    end
  end

  describe "#add" do
    it "adds values to an attribute" do
      attrs = SAML::Attributes.new
      attrs.add("role", ["admin"])
      attrs.add("role", ["user"])

      attrs.multi("role").should eq ["admin", "user"]
    end
  end

  describe "#set" do
    it "sets attribute values" do
      attrs = SAML::Attributes.new
      attrs.set("name", ["Alice"])
      attrs["name"].should eq "Alice"
    end

    it "overwrites existing values" do
      attrs = SAML::Attributes.new
      attrs.set("name", ["Alice"])
      attrs.set("name", ["Bob"])
      attrs["name"].should eq "Bob"
    end
  end

  describe "#includes?" do
    it "checks for attribute presence" do
      attrs = SAML::Attributes.new
      attrs.add("email", ["test@example.com"])

      attrs.includes?("email").should be_true
      attrs.includes?("phone").should be_false
    end

    it "works with symbols" do
      attrs = SAML::Attributes.new
      attrs.add("email", ["test@example.com"])

      attrs.includes?(:email).should be_true
    end
  end

  describe "#single and #multi" do
    it "single returns first value" do
      attrs = SAML::Attributes.new
      attrs.add("colors", ["red", "blue", "green"])

      attrs.single("colors").should eq "red"
    end

    it "multi returns all values" do
      attrs = SAML::Attributes.new
      attrs.add("colors", ["red", "blue", "green"])

      attrs.multi("colors").should eq ["red", "blue", "green"]
    end
  end

  describe "#fetch" do
    it "fetches by string name" do
      attrs = SAML::Attributes.new
      attrs.add("email", ["test@example.com"])

      attrs.fetch("email").should eq "test@example.com"
    end

    it "fetches by regex" do
      attrs = SAML::Attributes.new
      attrs.add("user:email", ["test@example.com"])

      attrs.fetch(/email/).should eq "test@example.com"
    end
  end

  describe "#==" do
    it "compares attributes collections" do
      attrs1 = SAML::Attributes.new({"name" => ["John"]})
      attrs2 = SAML::Attributes.new({"name" => ["John"]})
      attrs3 = SAML::Attributes.new({"name" => ["Jane"]})

      attrs1.should eq attrs2
      attrs1.should_not eq attrs3
    end
  end
end
