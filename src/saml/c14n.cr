# Canonical XML 1.1 Implementation
# Supports both Inclusive and Exclusive C14N
# Based on:
# - https://www.w3.org/TR/xml-c14n11/ (C14N 1.1)
# - https://www.w3.org/TR/xml-exc-c14n/ (Exclusive C14N)
#
# This implementation:
# - Pure Crystal, no libxml2 dependency
# - Proper xml:base fixups for subsets (absolutize & synthesize when needed)
# - Does not inherit xml:id (C14N 1.1 requirement)
# - Supports both Inclusive and Exclusive modes
# - Exclusive mode filters namespaces to only visibly utilized ones

require "xml"
require "uri"

module C14N
  VERSION = "1.1"

  XML_NS_URI   = "http://www.w3.org/XML/1998/namespace"
  XMLNS_NS_URI = "http://www.w3.org/2000/xmlns/"

  # Main canonicalization entry point
  #
  # @param xml [String] The XML document to canonicalize
  # @param exclusive [Bool] Use Exclusive C14N (default: true)
  # @param inclusive_prefixes [Array(String)] Prefixes to include in Exclusive mode
  # @param with_comments [Bool] Include comments in output
  # @param xpath [String?] XPath expression to select document subset
  # @return [String] Canonical XML string
  def self.c14n(
    xml : String,
    exclusive : Bool = true,
    inclusive_prefixes : Array(String) = [] of String,
    with_comments : Bool = false,
    xpath : String? = nil,
  ) : String
    builder = DOMBuilder.new
    root = builder.build(xml)
    raise "Empty XML document" unless root

    io = IO::Memory.new
    context = C14NContext.new(
      exclusive: exclusive,
      inclusive_prefixes: inclusive_prefixes.to_set,
      with_comments: with_comments
    )

    if xpath
      # TODO: Implement XPath-based subset selection
      # For now, canonicalize the whole document
      process_node(root, io, context)
    else
      process_node(root, io, context)
    end

    io.to_s
  end

  # Context for canonicalization state
  private class C14NContext
    property exclusive : Bool
    property inclusive_prefixes : Set(String)
    property with_comments : Bool

    # Stack of DECLARED namespaces (for resolution) - includes ALL declarations from ancestors
    property declared_ns_stack : Array(Hash(String, String))

    # Stack of RENDERED namespaces (for emission decisions) - only what we've actually emitted
    property rendered_ns_stack : Array(Hash(String, String))

    # Stack of effective xml:base values (for full document traversal)
    property eff_base_stack : Array(String?)

    # Stack of visible xml:base values (what we've emitted)
    property vis_base_stack : Array(String?)

    def initialize(@exclusive, @inclusive_prefixes, @with_comments)
      @declared_ns_stack = [Hash(String, String).new]
      @rendered_ns_stack = [Hash(String, String).new]
      @eff_base_stack = [nil.as(String?)]
      @vis_base_stack = [nil.as(String?)]
    end

    def declared_scope
      @declared_ns_stack.last
    end

    def rendered_scope
      @rendered_ns_stack.last
    end

    def push_declared_scope(new_decls : Hash(String, String))
      # Merge new declarations with parent scope
      scope = declared_scope.dup
      new_decls.each { |k, v| scope[k] = v }
      @declared_ns_stack << scope
    end

    def push_rendered_scope
      @rendered_ns_stack << rendered_scope.dup
    end

    def pop_declared_scope
      @declared_ns_stack.pop if @declared_ns_stack.size > 1
    end

    def pop_rendered_scope
      @rendered_ns_stack.pop if @rendered_ns_stack.size > 1
    end

    def eff_base
      @eff_base_stack.last
    end

    def vis_base
      @vis_base_stack.last
    end

    def push_eff_base(base : String?)
      @eff_base_stack << base
    end

    def pop_eff_base
      @eff_base_stack.pop if @eff_base_stack.size > 1
    end

    def push_vis_base(base : String?)
      @vis_base_stack << base
    end

    def pop_vis_base
      @vis_base_stack.pop if @vis_base_stack.size > 1
    end
  end

  # Abstract base node
  private abstract class Node
    property parent : ElementNode?

    def initialize(@parent : ElementNode?); end
  end

  # Text node
  private class TextNode < Node
    property text : String

    def initialize(@text : String, parent : ElementNode?)
      super(parent)
    end
  end

  # Comment node
  private class CommentNode < Node
    property text : String

    def initialize(@text : String, parent : ElementNode?)
      super(parent)
    end
  end

  # Processing instruction node
  private class PINode < Node
    property target : String
    property content : String

    def initialize(@target : String, @content : String, parent : ElementNode?)
      super(parent)
    end
  end

  # Attribute
  private class Attr
    property prefix : String?
    property local : String
    property uri : String?
    property value : String

    def initialize(@prefix, @local, @uri, @value); end

    def qname : String
      prefix ? "#{prefix}:#{local}" : local
    end

    def xml_ns? : Bool
      uri == XML_NS_URI
    end

    def is_xml_base? : Bool
      xml_ns? && local == "base"
    end

    def is_xml_id? : Bool
      xml_ns? && local == "id"
    end

    def is_xmlns? : Bool
      qname == "xmlns" || prefix == "xmlns"
    end
  end

  # Element node
  private class ElementNode < Node
    property prefix : String?
    property local : String
    property uri : String?
    property children : Array(Node)
    property attrs : Array(Attr)

    # Namespace declarations actually present on this element
    property ns_decl : Hash(String, String)

    # Raw xml:base value as parsed
    property xml_base_value : String?

    def initialize(@prefix, @local, @uri, parent : ElementNode?)
      super(parent)
      @children = [] of Node
      @attrs = [] of Attr
      @ns_decl = {} of String => String
    end

    def qname : String
      prefix ? "#{prefix}:#{local}" : local
    end
  end

  # DOM builder that preserves namespace information
  private class DOMBuilder
    property root : ElementNode?

    def initialize
      @root = nil
      @ns_stack = [Hash(String, String).new]
    end

    def build(xml : String) : ElementNode?
      doc = XML.parse(xml)
      root_node = doc.first_element_child
      return nil unless root_node

      # Build our internal representation
      build_element(root_node, nil)
    end

    private def build_element(xml_node : XML::Node, parent : ElementNode?) : ElementNode
      # Get element name parts from namespace object
      el_local = xml_node.name
      el_prefix = xml_node.namespace.try(&.prefix)
      el_uri = xml_node.namespace.try(&.href)

      # Build new namespace scope
      scope = @ns_stack.last.dup
      el = ElementNode.new(el_prefix, el_local, el_uri, parent)

      # Collect namespace declarations
      # Crystal's XML parser handles namespaces but we need to track declarations
      # We'll discover them through namespace_definitions if available
      xml_node.namespace_definitions.each do |ns_def|
        prefix = ns_def.prefix || ""
        href = ns_def.href || ""
        scope[prefix] = href
        el.ns_decl[prefix] = href
      end

      @ns_stack << scope

      # Process attributes
      xml_node.attributes.each do |attr|
        # Get attribute name parts
        a_local = attr.name
        a_prefix = nil.as(String?)
        a_uri = nil.as(String?)

        # Check if attribute has namespace
        if attr.namespace
          ns = attr.namespace.not_nil!
          a_prefix = ns.prefix
          a_uri = ns.href
        else
          # Check if it's a prefixed attribute without namespace object
          if idx = a_local.index(':')
            a_prefix = a_local[0...idx]
            a_local = a_local[idx + 1..-1]
            a_uri = resolve_uri(scope, a_prefix)
          end
        end

        attr_obj = Attr.new(a_prefix, a_local, a_uri, attr.content)
        el.attrs << attr_obj

        # Track xml:base
        el.xml_base_value = attr.content if attr_obj.is_xml_base?
      end

      # Process children
      xml_node.children.each do |child|
        case child.type
        when XML::Node::Type::ELEMENT_NODE
          el.children << build_element(child, el)
        when XML::Node::Type::TEXT_NODE, XML::Node::Type::CDATA_SECTION_NODE
          # Whitespace-only text nodes are part of the canonical form (C14N
          # emits every text node in the subset verbatim). Dropping them
          # breaks verification of signatures from Apache Santuario
          # (Shibboleth, Okta, ...), which put newlines between SignedInfo
          # children and sign those bytes.
          el.children << TextNode.new(child.content, el)
        when XML::Node::Type::COMMENT_NODE
          el.children << CommentNode.new(child.content, el)
        when XML::Node::Type::PI_NODE
          el.children << PINode.new(child.name, child.content || "", el)
        end
      end

      @ns_stack.pop
      el
    end

    private def split_qname(qname : String) : {String?, String}
      if idx = qname.index(':')
        {qname[0...idx], qname[idx + 1..-1]}
      else
        {nil, qname}
      end
    end

    private def resolve_uri(scope : Hash(String, String), prefix : String?) : String?
      if prefix
        scope[prefix]?
      else
        scope[""]?
      end
    end
  end

  # Process a node and its children
  private def self.process_node(node : Node, io : IO, ctx : C14NContext)
    case node
    when ElementNode
      process_element(node, io, ctx)
    when TextNode
      io << escape_text(node.text)
    when CommentNode
      if ctx.with_comments
        io << "<!--" << escape_comment(node.text) << "-->"
      end
    when PINode
      io << "<?" << node.target
      io << " " << node.content unless node.content.empty?
      io << "?>"
    end
  end

  # Process an element node
  private def self.process_element(elem : ElementNode, io : IO, ctx : C14NContext)
    # Push declared scope with this element's namespace declarations
    ctx.push_declared_scope(elem.ns_decl)
    ctx.push_rendered_scope

    # --- Step 1: Compute effective xml:base (for full document) ---
    parent_eff_base = ctx.eff_base
    eff_base = compute_effective_base(elem.xml_base_value, parent_eff_base)
    ctx.push_eff_base(eff_base)

    # --- Step 2: Determine which namespaces to emit ---
    ns_to_emit = compute_namespaces_to_emit(elem, ctx)

    # --- Step 3: Handle xml:base for C14N 1.1 ---
    vis_parent_base = ctx.vis_base
    xml_base_to_emit = compute_xml_base_to_emit(elem, eff_base, vis_parent_base)

    # --- Step 4: Emit start tag ---
    io << "<" << elem.qname

    # --- Step 4a: Emit namespace declarations ---
    emit_namespaces(ns_to_emit, io, ctx)

    # --- Step 4b: Emit attributes ---
    emit_attributes(elem, xml_base_to_emit, io, ctx)

    io << ">"

    # --- Step 5: Track visible base for children ---
    vis_next = xml_base_to_emit || vis_parent_base
    ctx.push_vis_base(vis_next)

    # --- Step 6: Process children ---
    elem.children.each do |child|
      process_node(child, io, ctx)
    end

    # --- Step 7: Emit end tag ---
    io << "</" << elem.qname << ">"

    # --- Cleanup ---
    ctx.pop_vis_base
    ctx.pop_eff_base
    ctx.pop_rendered_scope
    ctx.pop_declared_scope
  end

  # Compute effective xml:base value (absolute URI)
  private def self.compute_effective_base(raw_base : String?, parent_base : String?) : String?
    return parent_base if raw_base.nil? || raw_base.empty?
    absolutize_uri(raw_base, parent_base)
  end

  # Determine which namespaces need to be emitted
  private def self.compute_namespaces_to_emit(elem : ElementNode, ctx : C14NContext) : Hash(String, String)
    ns_to_emit = {} of String => String

    # Declared scope = all namespace declarations available for resolution
    declared = ctx.declared_scope

    # Rendered scope = what we've actually emitted so far
    rendered = ctx.rendered_scope

    # Collect visibly utilized namespaces
    utilized = collect_utilized_namespaces(elem)

    # Add inclusive prefixes in exclusive mode
    if ctx.exclusive
      ctx.inclusive_prefixes.each do |prefix|
        utilized << prefix unless prefix.empty?
      end
    end

    # DEBUG
    # STDERR.puts "Element: #{elem.qname}"
    # STDERR.puts "  Utilized: #{utilized.to_a}"
    # STDERR.puts "  Declared: #{declared}"
    # STDERR.puts "  Rendered: #{rendered}"

    if ctx.exclusive
      # Exclusive C14N: Only emit visibly utilized namespaces
      utilized.each do |prefix|
        next if prefix == "xml" # xml prefix is implicitly declared

        if uri = declared[prefix]?
          # Emit if not already rendered or if changed
          if rendered[prefix]? != uri
            ns_to_emit[prefix] = uri
            rendered[prefix] = uri
          end
        end
      end

      # Handle default namespace for element if no prefix
      if elem.prefix.nil?
        if uri = elem.uri
          current_uri = rendered[""]? || ""
          if current_uri != uri
            ns_to_emit[""] = uri
            rendered[""] = uri
          end
        end
      end
    else
      # Inclusive C14N: Emit all namespace declarations from this element
      elem.ns_decl.each do |prefix, uri|
        if rendered[prefix]? != uri
          ns_to_emit[prefix] = uri
          rendered[prefix] = uri
        end
      end
    end

    # DEBUG
    # STDERR.puts "  To-emit: #{ns_to_emit}"

    ns_to_emit
  end

  # Collect all visibly utilized namespace prefixes
  private def self.collect_utilized_namespaces(elem : ElementNode) : Set(String)
    utilized = Set(String).new

    # Element's namespace
    if prefix = elem.prefix
      utilized << prefix
    end

    # Attribute namespaces (non-xmlns)
    elem.attrs.each do |attr|
      next if attr.is_xmlns?
      if prefix = attr.prefix
        utilized << prefix unless prefix == "xml"
      end
    end

    utilized
  end

  # Compute xml:base value to emit (if any)
  private def self.compute_xml_base_to_emit(elem : ElementNode, eff_base : String?, vis_parent_base : String?) : String?
    # If element has xml:base attribute, absolutize and return it
    if base_attr = elem.attrs.find(&.is_xml_base?)
      abs = absolutize_uri(base_attr.value, vis_parent_base)
      # Update attribute value to absolute form
      base_attr.value = abs
      return abs
    end

    # If effective base differs from visible parent base, synthesize xml:base
    if eff_base && eff_base != vis_parent_base
      return eff_base
    end

    nil
  end

  # Emit namespace declarations in sorted order
  private def self.emit_namespaces(ns_to_emit : Hash(String, String), io : IO, ctx : C14NContext)
    # Sort: default namespace ("") first, then by prefix
    sorted = ns_to_emit.to_a.sort_by { |prefix, uri| prefix.empty? ? "\x00" : prefix }

    sorted.each do |prefix, uri|
      if prefix.empty?
        io << %( xmlns=")
      else
        io << %( xmlns:#{prefix}=")
      end
      io << escape_attr(uri) << %(")
    end
  end

  # Emit attributes in canonical order
  private def self.emit_attributes(elem : ElementNode, xml_base_to_emit : String?, io : IO, ctx : C14NContext)
    attrs = elem.attrs.reject(&.is_xmlns?)

    # If we need to synthesize xml:base, add it
    if xml_base_to_emit && !attrs.any?(&.is_xml_base?)
      attrs << Attr.new("xml", "base", XML_NS_URI, xml_base_to_emit)
    end

    # Do NOT inherit xml:id (C14N 1.1 requirement)
    # We only emit xml:id if it's explicitly on this element

    # Sort by (namespace URI, local name)
    attrs.sort_by! { |a| [a.uri || "", a.local] }

    attrs.each do |attr|
      io << " " << attr.qname << %(=") << escape_attr(attr.value) << %(")
    end
  end

  # Absolutize a URI against a base URI
  private def self.absolutize_uri(uri : String, base : String?) : String
    return uri if uri.empty?

    begin
      parsed = URI.parse(uri)

      # If URI has scheme, it's already absolute
      return normalize_uri(parsed).to_s if parsed.scheme

      # Resolve against base
      if base
        base_uri = URI.parse(base)
        resolved = base_uri.resolve(parsed)
        return normalize_uri(resolved).to_s
      end
    rescue
      # If parsing fails, return as-is
    end

    uri
  end

  # Normalize URI (remove dot segments, etc.)
  private def self.normalize_uri(uri : URI) : URI
    # Ensure path starts with "/" if there's a host
    if uri.host && (uri.path.nil? || uri.path.to_s.empty?)
      uri = uri.dup
      uri.path = "/"
    end
    uri
  end

  # Escape text content
  private def self.escape_text(text : String) : String
    String.build do |io|
      text.each_char do |ch|
        case ch
        when '&'  then io << "&amp;"
        when '<'  then io << "&lt;"
        when '>'  then io << "&gt;"
        when '\r' then io << "&#xD;"
        else           io << ch
        end
      end
    end
  end

  # Escape attribute values
  private def self.escape_attr(value : String) : String
    String.build do |io|
      value.each_char do |ch|
        case ch
        when '&'  then io << "&amp;"
        when '<'  then io << "&lt;"
        when '"'  then io << "&quot;"
        when '\t' then io << "&#x9;"
        when '\n' then io << "&#xA;"
        when '\r' then io << "&#xD;"
        else           io << ch
        end
      end
    end
  end

  # Escape comment content
  private def self.escape_comment(text : String) : String
    # Comments shouldn't contain "--" but if they do, escape it
    text.gsub("--", "- -")
  end
end
