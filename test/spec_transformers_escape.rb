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

$:.unshift("#{File.expand_path(File.dirname(__FILE__))}/../lib")
require 'bacon'
require '../lib/sanitize.rb'

# Whitelisting <span> tags so I can test that
# escape handles transformers whitelisting things
# correctly.
#
# Note: At the moment, :whitelist_nodes adds to the node whitelist array and is 
#       accessible to subsequent transformers. :whitelist => true does not register
#       the node into this list, though - and it does NOT carry between transformers.
#
#       Additionally, the node being present in @whitelist_nodes causes Sanitize to 
#       skip attribute validation on it, whereas :whitelist => true still runs them.
#       So, :whitelist => true is more secure but it doesn't play nicely with other
#       transformers. 
#
simple_whitelist_transformer = lambda { |env| return {:whitelist_nodes => [env[:node]]} if env[:node_name] == 'span' }
#simple_whitelist_transformer = lambda { |env| return {:whitelist => true} if env[:node_name] == 'span' }

strings = {
  :most_simple => {
    :html       => '<strong>Hello, world.</strong>',
    :default    => '&lt;strong&gt;Hello, world.&lt;/strong&gt;',
    :restricted => '<strong>Hello, world.</strong>',
    :transform  => '<strong>Hello, world.</strong>',
    :basic      => '<strong>Hello, world.</strong>',
    :relaxed    => '<strong>Hello, world.</strong>'
  },
  :neuter_inner_tags => {
    :html       => '<strong><div>Hello World</div></strong>',
    :default    => '&lt;strong&gt;&lt;div&gt;Hello World&lt;/div&gt;&lt;/strong&gt;',
    :restricted => '<strong>&lt;div&gt;Hello World&lt;/div&gt;</strong>',
    :transform  => '<strong>&lt;div&gt;Hello World&lt;/div&gt;</strong>',
    :basic      => '<strong>&lt;div&gt;Hello World&lt;/div&gt;</strong>',
    :relaxed    => '<strong>&lt;div&gt;Hello World&lt;/div&gt;</strong>',
  },

  :neuter_nested => {
    :html       => '<strong>Hello, <em><div>my friend</div>.</em></strong>',
    :default    => '&lt;strong&gt;Hello, &lt;em&gt;&lt;div&gt;my friend&lt;/div&gt;.&lt;/em&gt;&lt;/strong&gt;',
    :restricted => '<strong>Hello, <em>&lt;div&gt;my friend&lt;/div&gt;.</em></strong>',
    :transform  => '<strong>Hello, <em>&lt;div&gt;my friend&lt;/div&gt;.</em></strong>',
    :basic      => '<strong>Hello, <em>&lt;div&gt;my friend&lt;/div&gt;.</em></strong>',
    :relaxed    => '<strong>Hello, <em>&lt;div&gt;my friend&lt;/div&gt;.</em></strong>',
  },

  # If something being neutered has attributes, they can stay - the
  # tag's been neutered, after all.
  :neuter_ignoring_attributes => {
    :html       => '<strong><div id="testid">_why</div></strong>',
    :default    => '&lt;strong&gt;&lt;div id="testid"&gt;_why&lt;/div&gt;&lt;/strong&gt;',
    :restricted => '<strong>&lt;div id="testid"&gt;_why&lt;/div&gt;</strong>',
    :transform  => '<strong>&lt;div id="testid"&gt;_why&lt;/div&gt;</strong>',
    :basic      => '<strong>&lt;div id="testid"&gt;_why&lt;/div&gt;</strong>',
    :relaxed    => '<strong>&lt;div id="testid"&gt;_why&lt;/div&gt;</strong>',
  },

  # Unbalanced tags get balanced. This really isn't the most desirable
  # behaviour (I don't want it balancing blacklisted things; I want them
  # neutered as-is), but Nokogiri does this itself before we get to the 
  # whitelist logic, so I don't have a choice in the matter.
  #
  # It's a DOM thing I guess; can't not do it. 
  :neuter_with_unbalanced_tags => {
    :html       => '<div><strong>Hello</div> world</strong>',
    :default    => '&lt;div&gt;&lt;strong&gt;Hello&lt;/strong&gt;&lt;/div&gt; world',
    :restricted => '&lt;div&gt;<strong>Hello</strong>&lt;/div&gt; world',
    :transform  => '&lt;div&gt;<strong>Hello</strong>&lt;/div&gt; world',
    :basic      => '&lt;div&gt;<strong>Hello</strong>&lt;/div&gt; world',
    :relaxed    => '&lt;div&gt;<strong>Hello</strong>&lt;/div&gt; world',
  },

  # I made this into a transformer. Even though the transformer runs, this
  # doesn't bypass the other filers, right? I'm not whitelisting anything explicitly...
  :still_adds_attributes? => {
    :html       => '<a>Click me</a>',
    :default    => '&lt;a&gt;Click me&lt;/a&gt;',
    :restricted => '&lt;a&gt;Click me&lt;/a&gt;',
    :transform  => '&lt;a&gt;Click me&lt;/a&gt;',
    :basic      => '<a rel="nofollow">Click me</a>',
    :relaxed    => '<a>Click me</a>',
  },
  
  :still_strips_attributes? => {
    :html       => '<b id="test">Hello</b>',
    :default    => '&lt;b id="test"&gt;Hello&lt;/b&gt;',
    :restricted => '<b>Hello</b>',
    :transform  => '<b>Hello</b>',
    :basic      => '<b>Hello</b>',
    :relaxed    => '<b>Hello</b>',
  },

  # These are to ensure escape is playing nicely with other
  # transformers whitelisting things.
  :span_passes? => {
    :html       => '<span>Hello</span>',
    :default    => '&lt;span&gt;Hello&lt;/span&gt;',
    :restricted => '&lt;span&gt;Hello&lt;/span&gt;',
    :transform  => '<span>Hello</span>',
    :basic      => '&lt;span&gt;Hello&lt;/span&gt;',
    :relaxed    => '&lt;span&gt;Hello&lt;/span&gt;',
  },

  :span_with_children => {
    :html       => '<span>This is <b>bold</b>!</span>',
    :default    => '&lt;span&gt;This is &lt;b&gt;bold&lt;/b&gt;!&lt;/span&gt;',
    :restricted => '&lt;span&gt;This is <b>bold</b>!&lt;/span&gt;',
    :transform  => '<span>This is <b>bold</b>!</span>',
    :basic      => '&lt;span&gt;This is <b>bold</b>!&lt;/span&gt;',
    :relaxed    => '&lt;span&gt;This is <b>bold</b>!&lt;/span&gt;',
  },

  :span_in_children => {
    :html       => '<b>Hi <span>Tim</span>.</b>',
    :default    => '&lt;b&gt;Hi &lt;span&gt;Tim&lt;/span&gt;.&lt;/b&gt;',
    :restricted => '<b>Hi &lt;span&gt;Tim&lt;/span&gt;.</b>',
    :transform  => '<b>Hi <span>Tim</span>.</b>',
    :basic      => '<b>Hi &lt;span&gt;Tim&lt;/span&gt;.</b>',
    :relaxed    => '<b>Hi &lt;span&gt;Tim&lt;/span&gt;.</b>',
  },

  :span_with_attributes => {
    :html       => '<span id="test">Hello</span>',
    :default    => '&lt;span id="test"&gt;Hello&lt;/span&gt;',
    :restricted => '&lt;span id="test"&gt;Hello&lt;/span&gt;',
    :transform  => '<span>Hello</span>',
    :basic      => '&lt;span id="test"&gt;Hello&lt;/span&gt;',
    :relaxed    => '&lt;span id="test"&gt;Hello&lt;/span&gt;',
  }
}

escape = {:transformers => [Sanitize::Transformers::ESCAPE]}
escape_with_prior = {:transformers => [simple_whitelist_transformer, Sanitize::Transformers::ESCAPE]}
describe 'Config::DEFAULT' do
  before { @s = Sanitize.new(escape) }

  strings.each do |name, data|
    should "clean #{name} HTML" do
      @s.clean(data[:html]).should.equal(data[:default])
    end
  end
end

describe 'Config::RESTRICTED' do
  before { @s = Sanitize.new(Sanitize::Config::RESTRICTED.merge(escape)) }

  strings.each do |name, data|
    should "clean #{name} HTML" do
      @s.clean(data[:html]).should.equal(data[:restricted])
    end
  end
end

describe 'Config::BASIC' do
  before { @s = Sanitize.new(Sanitize::Config::BASIC.merge(escape)) }

  strings.each do |name, data|
    should "clean #{name} HTML" do
      @s.clean(data[:html]).should.equal(data[:basic])
    end
  end
end

describe 'Config::RELAXED' do
  before { @s = Sanitize.new(Sanitize::Config::RELAXED.merge(escape)) }

  strings.each do |name, data|
    should "clean #{name} HTML" do
      @s.clean(data[:html]).should.equal(data[:relaxed])
    end
  end
end

describe 'Transformer whitelist' do
  before { @s = Sanitize.new(Sanitize::Config::RESTRICTED.merge(escape_with_prior)) }

  strings.each do |name, data|
    should "clean #{name} HTML" do
      @s.clean(data[:html]).should.equal(data[:transform])
    end
  end
end

