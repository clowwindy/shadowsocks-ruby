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

$encrypt_table, $decrypt_table = get_table(key)

def inet_ntoa(n)
    n.unpack("C*").join "."
end

module LocalServer
  class LocalConnector < EventMachine::Connection
    def initialize server
      @server = server
      super
    end

    def post_init
      p "connecting #{@server.remote_addr} via #{@server.server_using}"
      addr_to_send = @server.addr_to_send.clone
      encrypt $encrypt_table, addr_to_send
      send_data addr_to_send

      # TODO write cached pieces
      for piece in @server.cached_pieces
        encrypt $encrypt_table, piece
        send_data data
      end
      @server.cached_pieces = nil

      @server.stage = 5

    end

    def receive_data data
      encrypt $decrypt_table, data
      @server.send_data data
    end

    def unbind
      @server.close_connection_after_writing
    end
  end

  attr_accessor :remote_addr
  attr_accessor :remote_port
  attr_accessor :stage
  attr_accessor :addr_to_send
  attr_accessor :server_using
  attr_accessor :cached_pieces

  def post_init
    puts "local connected"
    @stage = 0
    @header_length = 0
    @remote = 0
    @cached_pieces = []
    @addr_len = 0
    @remote_addr = nil
    @remote_port = nil
    @connector = nil
    @addr_to_send = ""
    @server_using = $server
  end

  def receive_data data
    if @stage == 5
      encrypt $encrypt_table, data
      @connector.send_data data
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
        warn "unsupported cmd: " + cmd.unpack('c')[0].to_s
        close_connection
        return
      end
      if addrtype == "\x03"
        @addr_len = data[4].unpack('c')[0]
      elsif addrtype != "\x01"
        warn "unsupported addrtype: " + cmd.unpack('c')[0].to_s
        close_connection
        return
      end
      @addr_to_send = data[3]
      if addrtype == "\x01"
        @addr_to_send += data[4..9]
        @remote_addr = inet_ntoa data[4..7]
        @remote_port = data[8, 2].unpack('s>')[0]
        @header_length = 10
      else
        @remote_addr = data[5, @addr_len]
        @addr_to_send += data[4..5 + @addr_len + 2]
        @remote_port = data[5 + @addr_len, 2].unpack('s>')[0]
        @header_length = 5 + @addr_len + 2
      end
      #p @remote_addr, @remote_port
      #p @addr_to_send
      send_data "\x05\x00\x00\x01\x00\x00\x00\x00" + [@remote_port].pack('s>')
      @connector = EventMachine.connect $server, $remote_port, LocalConnector, self

      if data.size > @header_length
        @cached_pieces.push data[@header_length, data.size]
      end
      stage = 4
    elsif @stage == 4
      @cached_pieces.push data[@header_length, data.size]
    end

  end

  def unbind
    if @connector != nil
      @connector.close_connection_after_writing
    end

  end
end

EventMachine::run {
  EventMachine::start_server "127.0.0.1", $port, LocalServer
}