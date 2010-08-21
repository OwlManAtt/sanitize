# encoding: utf-8
#--
# Copyright (c) 2010 Ryan Grove <ryan@wonko.com>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the 'Software'), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#++

require 'nokogiri'
require 'sanitize/version'
require 'sanitize/config'
require 'sanitize/config/restricted'
require 'sanitize/config/basic'
require 'sanitize/config/relaxed'

class Sanitize
  attr_reader :config

  # Matches an attribute value that could be treated by a browser as a URL
  # with a protocol prefix, such as "http:" or "javascript:". Any string of zero
  # or more characters followed by a colon is considered a match, even if the
  # colon is encoded as an entity and even if it's an incomplete entity (which
  # IE6 and Opera will still parse).
  REGEX_PROTOCOL = /^([A-Za-z0-9\+\-\.\&\;\#\s]*?)(?:\:|&#0*58|&#x0*3a)/i

  #--
  # Class Methods
  #++

  # Returns a sanitized copy of _html_, using the settings in _config_ if
  # specified.
  def self.clean(html, config = {})
    sanitize = Sanitize.new(config)
    sanitize.clean(html)
  end

  # Performs Sanitize#clean in place, returning _html_, or +nil+ if no changes
  # were made.
  def self.clean!(html, config = {})
    sanitize = Sanitize.new(config)
    sanitize.clean!(html)
  end

  # Sanitizes the specified Nokogiri::XML::Node and all its children.
  def self.clean_node!(node, config = {})
    sanitize = Sanitize.new(config)
    sanitize.clean_node!(node)
  end

  #--
  # Instance Methods
  #++

  # Returns a new Sanitize object initialized with the settings in _config_.
  def initialize(config = {})
    # Sanitize configuration.
    @config = Config::DEFAULT.merge(config)
    @config[:transformers] = Array(@config[:transformers].dup)

    # Convert the list of allowed elements to a Hash for faster lookup.
    @allowed_elements = {}
    @config[:elements].each {|el| @allowed_elements[el] = true }

    # Convert the list of :remove_contents elements to a Hash for faster lookup.
    @remove_all_contents     = false
    @remove_element_contents = {}

    if @config[:remove_contents].is_a?(Array)
      @config[:remove_contents].each {|el| @remove_element_contents[el] = true }
    else
      @remove_all_contents = !!@config[:remove_contents]
    end

    # Specific nodes to whitelist (along with all their attributes). This array
    # is generated at runtime by transformers, and is cleared before and after
    # a fragment is cleaned (so it applies only to a specific fragment).
    @whitelist_nodes = []
  end

  # Returns a sanitized copy of _html_.
  def clean(html)
    if html
      dupe = html.dup
      clean!(dupe) || dupe
    end
  end

  # Performs clean in place, returning _html_, or +nil+ if no changes were
  # made.
  def clean!(html)
    fragment = Nokogiri::HTML::DocumentFragment.parse(html)
    clean_node!(fragment)

    output_method_params = {:encoding => @config[:output_encoding], :indent => 0}

    if @config[:output] == :xhtml
      output_method = fragment.method(:to_xhtml)
      output_method_params[:save_with] = Nokogiri::XML::Node::SaveOptions::AS_XHTML
    elsif @config[:output] == :html
      output_method = fragment.method(:to_html)
    else
      raise Error, "unsupported output format: #{@config[:output]}"
    end

    result = output_method.call(output_method_params)

    return result == html ? nil : html[0, html.length] = result
  end

  # Sanitizes the specified Nokogiri::XML::Node and all its children.
  def clean_node!(node)
    raise ArgumentError unless node.is_a?(Nokogiri::XML::Node)

    @whitelist_nodes = []

    node.traverse do |child|
      if child.element?
        clean_element!(child)
      elsif child.comment?
        child.unlink unless @config[:allow_comments]
      elsif child.cdata?
        child.replace(Nokogiri::XML::Text.new(child.text, child.document))
      end
    end

    @whitelist_nodes = []

    node
  end

  private

  def clean_element!(node)
    # Run this node through all configured transformers.
    transform = transform_element!(node)

    # If this node is in the dynamic whitelist array (built at runtime by
    # transformers), let it live with all of its attributes intact.
    return if @whitelist_nodes.include?(node)

    name = node.name.to_s.downcase

    # Delete any element that isn't in the whitelist.
    unless transform[:whitelist] || @allowed_elements[name]
      if @config[:escape_only] 
        # I tried avoiding this by node.dup(2)ing (that copies the element
        # without its children) and then only moving the children from the node
        # to their new position in the tree (at the childs.each { add_blabla_sibling }
        # part), but that didn't help performance at all. I guess it's clever
        # about managing memory here?
        #
        # Regardless, :escape_only is REALLY REALLY SLOW when dealing with 'large'
        # HTML docs - I'd define large as anything with lots and lots of children.
        # Moving them to their new spots in the DOM is probably what makes it suck
        # so badly. Here's what I mean:
        #
        #  Big HTML doc (149413 bytes) x 100
        #                             total    single    rel
        #    Sanitize.clean (strip)   19.025 (0.190254)     -
        #    Sanitize.clean (prune)   11.194 (0.111939)  0.59x
        #    Sanitize.clean (escape)  33.436 (0.334364)  1.76x
        #
        # Still, it's about the same as strip for sane-sized things. Perfectly
        # fine for cleaning up forum posts and stuff.
        childs = node.children.remove

        if @config[:output] == :xhtml
          node_text = node.to_xhtml
        elsif @config[:output] == :html
          node_text = node.to_html
        end

        # This is a pretty :awesome: hack. I consider it 'OK' since Nokogiri is 
        # handling the rendering of tags and escaping of HTML entities...but 
        # still, I am a terrible person for doing these vulgar string operations
        # in a library that was otherwise quite elegant. 
        if node_text.include? '><' # has a closing tag?
          size = node.name.length + 3 # 3 for </>

          # I originally tried NodeSet.before() / NodeSet.after() so they'd be
          # added in the childs' each block but the text nodes I added 
          # disappeared in to thin air...maybe it doesn't like adding Text objects
          # to nodesets? I dunno.
          node.add_previous_sibling(Nokogiri::XML::Text.new(node_text[0,node_text.length-size], node.document)) 
          childs.each { |c| node.add_previous_sibling(c) }
          node.add_previous_sibling(Nokogiri::XML::Text.new(node_text[-size,size], node.document)) 

        else
          # <br>, <img>, etc. 
          # I have no idea if they can have children (well, I mean, they won't be 
          # valid HTML if they do, but does Nokogiri clean that up or what?).
          # So, better safe than sorry.
          node.add_previous_sibling(Nokogiri::XML::Text.new(node_text, node.document))
          childs.each { |c| node.add_previous_sibling(c) }
        end
      else
        unless @remove_all_contents || @remove_element_contents[name]
          node.children.each { |n| node.add_previous_sibling(n) }
        end
      end

      node.unlink

      return
    end

    attr_whitelist = (transform[:attr_whitelist] +
        (@config[:attributes][name] || []) +
        (@config[:attributes][:all] || [])).uniq

    if attr_whitelist.empty?
      # Delete all attributes from elements with no whitelisted attributes.
      node.attribute_nodes.each {|attr| attr.remove }
    else
      # Delete any attribute that isn't in the whitelist for this element.
      node.attribute_nodes.each do |attr|
        attr.unlink unless attr_whitelist.include?(attr.name.downcase)
      end

      # Delete remaining attributes that use unacceptable protocols.
      if @config[:protocols].has_key?(name)
        protocol = @config[:protocols][name]

        node.attribute_nodes.each do |attr|
          attr_name = attr.name.downcase
          next false unless protocol.has_key?(attr_name)

          del = if attr.value.to_s.downcase =~ REGEX_PROTOCOL
            !protocol[attr_name].include?($1.downcase)
          else
            !protocol[attr_name].include?(:relative)
          end

          attr.unlink if del
        end
      end
    end

    # Add required attributes.
    if @config[:add_attributes].has_key?(name)
      @config[:add_attributes][name].each do |key, val|
        node[key] = val
      end
    end

    transform
  end

  def transform_element!(node)
    output = {
      :attr_whitelist => [],
      :node           => node,
      :whitelist      => false
    }

    @config[:transformers].inject(node) do |transformer_node, transformer|
      transform = transformer.call({
        :config    => @config,
        :node      => transformer_node,
        :node_name => transformer_node.name.downcase
      })

      if transform.nil?
        transformer_node
      elsif transform.is_a?(Hash)
        if transform[:whitelist_nodes].is_a?(Array)
          @whitelist_nodes += transform[:whitelist_nodes]
          @whitelist_nodes.uniq!
        end

        output[:attr_whitelist]  += transform[:attr_whitelist] if transform[:attr_whitelist].is_a?(Array)
        output[:whitelist]      ||= true if transform[:whitelist]
        output[:node]             = transform[:node].is_a?(Nokogiri::XML::Node) ? transform[:node] : output[:node]
      else
        raise Error, "transformer output must be a Hash or nil"
      end
    end

    node.replace(output[:node]) if node != output[:node]

    return output
  end

  class Error < StandardError; end
end
