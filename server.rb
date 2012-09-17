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
require 'json'
require './encrypt'

cfg_file = File.open('config.json')
config = JSON.parse(cfg_file.read)
cfg_file.close

key = config['password']

$remote_port = config['server_port'].to_i

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

      for piece in @server.cached_pieces
        send_data piece
      end
      @server.cached_pieces = nil

      @server.stage = 5
    end

    def receive_data data
      encrypt $encrypt_table, data
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
    @remote_addr = nil
    @remote_port = nil
    @connector = nil
    @addr_to_send = ""
    @server_using = $server
  end

  def receive_data data
    encrypt $decrypt_table, data
    if @stage == 5
      @connector.send_data data
      return
    end
    if @stage == 0
      begin
        addr_len = 0
        addrtype = data[0]
        if addrtype == "\x03"
          addr_len = data[1].unpack('c')[0]
        elsif addrtype != "\x01"
          warn "unsupported addrtype: " + addrtype.unpack('c')[0].to_s
          close_connection
          return
        end
        if addrtype == "\x01"
          @remote_addr = inet_ntoa data[1..4]
          @remote_port = data[5, 2].unpack('s>')[0]
          @header_length = 7
        else
          @remote_addr = data[2, addr_len]
          @remote_port = data[2 + addr_len, 2].unpack('s>')[0]
          @header_length = 2 + addr_len + 2
        end
        @stage = 4
        if data.size > @header_length
          @cached_pieces.push data[@header_length, data.size]
        end

        @connector = EventMachine.connect @remote_addr, @remote_port, LocalConnector, self
      rescue Exception => e
        warn e
        if @connector != nil
          @connector.close_connection
        end
        close_connection
      end
    elsif @stage == 4
      @cached_pieces.push data
    end

  end

  def unbind
    if @connector != nil
      @connector.close_connection_after_writing
    end

  end
end

EventMachine::run {
  EventMachine::start_server "0.0.0.0", $remote_port, LocalServer
}