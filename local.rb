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

require 'rubygems'
require 'eventmachine'
require './encrypt'

key = 'onebox!'

$server = '106.187.51.232'
$remote_port = 8388
$port = 1080

encrypt_table, decrypt_table = get_table(key)

module LocalServer
  class LocalConnector < EventMachine::Connection

  end

  def post_init
    puts "local connected"
    @stage = 0
    @header_length = 0
    @remote = 0
    @cached_pieces = []
    @addr_len = 0
    @remote_addr = nil
    @remote_port = nil
    @addr_to_send = ""
    @server_using = $server
  end

  def receive_data data
    p @stage
    if @stage == 5
      encrypt table, data
      @connection.send_data data
      return
    end
    if @stage == 0
      send_data "\x05\x00"
      @stage = 1
      return
    end
    if @stage == 1
      cmd = data[1]
      addrtype = data[3]
      if cmd != "\x01"
        warn "unsupported cmd: " + cmd.unpack('c')
        close_connection
        return
      end
      if addrtype == "\x03"
        @addr_len = data[4].unpack('c')[0]
      elsif addrtype != 1
        warn "unsupported addrtype: " + cmd.unpack('c')
        close_connection
        return
      end
      @addr_to_send = data[3..4]
      p data
      if addrtype == "\x01"
        @addr_to_send += data[4..10]
        @remote_port = data[8, 2].unpack('s>')[0]
        @header_length = 10
      else
        @remote_addr = data[5, @addr_len]
        @addr_to_send += data[4..5 + @addr_len + 2]
        @remote_port = data[5 + @addr_len, 2].unpack('s>')[0]
        @header_length = 5 + @addr_len + 2
      end
      p @remote_addr, @remote_port
      p @addr_to_send
    end

  end

  def unbind

  end
end

EventMachine::run {
  EventMachine::start_server "127.0.0.1", $port, LocalServer
}