#!/usr/bin/ruby

# Copyright (c) 2012 clowwindy
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

require "digest"
require "./merge_sort"

def get_table (key)
  table = Array.new(256, 0)
  decrypt_table = Array.new(256, 0)

  a = Digest::MD5.digest(key).unpack('Q<')[0]
  i = 0

  while i < 256
    table[i] = i
    i += 1
  end
  i = 1

  while i < 1024
    table = merge_sort(table, lambda { |x, y|
      a % (x + i) - a % (y + i)
    })
    i += 1
  end
  i = 0
  while i < 256
    decrypt_table[table[i]] = i
    i += 1
  end
  [table, decrypt_table]
end

def encrypt (table, buf)
  i = 0

  while i < buf.length
    buf[i] = table[buf[i]]
    i += 1
  end
end


