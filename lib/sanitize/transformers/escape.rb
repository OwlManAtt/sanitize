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

class Sanitize
  module Transformers
    ESCAPE = lambda do |env|
      allowed_elements = env[:config][:elements]
      format = env[:config][:output]
      node = env[:node]

      # No action will be taken. It's been allowed by the config or
      # a transformer that's already run. 
      #
      # TODO: wait shit, env doesn't pass in the whitelisted node list so
      #       other transformers that run before us get ignored...
      return if allowed_elements.include? env[:node_name]
      #return nil if @whitelist_nodes.include?(node)

      # ESCAPE is rather slow when dealing with 'large' HTML
      # docs - I'd define large as anything with lots and lots of children.
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

      if format == :xhtml
        node_text = node.to_xhtml
      elsif format == :html
        node_text = node.to_html
      end

      # This, right here, is a hack. It's not too terrible since Nokogiri is
      # still handling the tag generation / escaping stuff, so it's safe.
      # We're splitting the tag up and putting it in Text elements, then 
      # appending/prepending them in the DOM so the final result will look like
      # what you'd expect.
      if node_text.include? '><'
        size = node.name.length + 3 # 3 for </>

        # I originally tried childs.before() / childs.after() so they'd be
        # added by the childs.each block but the text nodes I added disappeared
        # in to thin air... 
        node.add_previous_sibling(Nokogiri::XML::Text.new(node_text[0,node_text.length-size], node.document)) 
        childs.each { |c| node.add_previous_sibling(c) }
        node.add_previous_sibling(Nokogiri::XML::Text.new(node_text[-size,size], node.document)) 
      else
        # <br>, <img>, etc. Nokogiri cleans these up so they will never have children. 
        node.add_previous_sibling(Nokogiri::XML::Text.new(node_text, node.document))
      end

      node.unlink
      return
    end
  end
end
