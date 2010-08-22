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

require 'bacon'
require '../lib/sanitize.rb'

strings = {
  :most_simple => {
    :html       => '<strong>Hello, world.</strong>',
    :default    => '&lt;strong&gt;Hello, world.&lt;/strong&gt;',
    :restricted => '<strong>Hello, world.</strong>',
    :basic      => '<strong>Hello, world.</strong>',
    :relaxed    => '<strong>Hello, world.</strong>'
  },
  :neuter_inner_tags => {
    :html       => '<strong><div>Hello World</div></strong>',
    :default    => '&lt;strong&gt;&lt;div&gt;Hello World&lt;/div&gt;&lt;/strong&gt;',
    :restricted => '<strong>&lt;div&gt;Hello World&lt;/div&gt;</strong>',
    :basic      => '<strong>&lt;div&gt;Hello World&lt;/div&gt;</strong>',
    :relaxed    => '<strong>&lt;div&gt;Hello World&lt;/div&gt;</strong>',
  },

  :neuter_nested => {
    :html       => '<strong>Hello, <em><div>my friend</div>.</em></strong>',
    :default    => '&lt;strong&gt;Hello, &lt;em&gt;&lt;div&gt;my friend&lt;/div&gt;.&lt;/em&gt;&lt;/strong&gt;',
    :restricted => '<strong>Hello, <em>&lt;div&gt;my friend&lt;/div&gt;.</em></strong>',
    :basic      => '<strong>Hello, <em>&lt;div&gt;my friend&lt;/div&gt;.</em></strong>',
    :relaxed    => '<strong>Hello, <em>&lt;div&gt;my friend&lt;/div&gt;.</em></strong>',
  },

  # If something being neutered has attributes, they can stay - the
  # tag's been neutered, after all.
  :neuter_ignoring_attributes => {
    :html       => '<strong><div id="testid">_why</div></strong>',
    :default    => '&lt;strong&gt;&lt;div id="testid"&gt;_why&lt;/div&gt;&lt;/strong&gt;',
    :restricted => '<strong>&lt;div id="testid"&gt;_why&lt;/div&gt;</strong>',
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
    :basic      => '&lt;div&gt;<strong>Hello</strong>&lt;/div&gt; world',
    :relaxed    => '&lt;div&gt;<strong>Hello</strong>&lt;/div&gt; world',
  }
}

describe 'Config::DEFAULT' do
  before { @s = Sanitize.new({:escape_only => true}) }

  strings.each do |name, data|
    should "clean #{name} HTML" do
      @s.clean(data[:html]).should.equal(data[:default])
    end
  end
end

describe 'Config::RESTRICTED' do
  before { @s = Sanitize.new(Sanitize::Config::BASIC.merge({:escape_only => true})) }

  strings.each do |name, data|
    should "clean #{name} HTML" do
      @s.clean(data[:html]).should.equal(data[:restricted])
    end
  end
end

describe 'Config::BASIC' do
  before { @s = Sanitize.new(Sanitize::Config::BASIC.merge({:escape_only => true})) }

  strings.each do |name, data|
    should "clean #{name} HTML" do
      @s.clean(data[:html]).should.equal(data[:basic])
    end
  end
end

describe 'Config::RELAXED' do
  before { @s = Sanitize.new(Sanitize::Config::RELAXED.merge({:escape_only => true})) }

  strings.each do |name, data|
    should "clean #{name} HTML" do
      @s.clean(data[:html]).should.equal(data[:relaxed])
    end
  end
end
